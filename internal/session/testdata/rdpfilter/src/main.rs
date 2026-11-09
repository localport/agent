// Prints, one per line as `<name> <hex>`, the RDP PDUs the rdp filter tests
// replay. A session `<variant>.<nn>.<c|s>` is the post-security-upgrade
// transcript of an IronRDP client connecting to an IronRDP server, one line
// per step, `c` for client to server and `s` for server to client. Every
// other name is one static channel message encoded for the `base` session's
// channel ids: `c.` lines as the client encodes them, `s.` lines as the
// server does.
use std::any::Any;
use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use ironrdp_acceptor::Acceptor;
use ironrdp_cliprdr::pdu::{
    Capabilities, ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    ClipboardPdu, ClipboardProtocolVersion, ClientTemporaryDirectory, FileContentsFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, FormatList, FormatListResponse, LockDataId,
};
use ironrdp_connector::{ClientConnector, Config, Credentials, DesktopSize, Sequence};
use ironrdp_core::{WriteBuf, encode_vec, impl_as_any};
use ironrdp_dvc::pdu::{
    CapabilitiesRequestPdu, CapabilitiesResponsePdu, CapsVersion, ClosePdu, CreateRequestPdu, CreateResponsePdu,
    CreationStatus, DataCompressedPdu, DataFirstPdu, DataPdu, DrdynvcClientPdu, DrdynvcDataPdu, DrdynvcServerPdu,
    SoftSyncChannelList, SoftSyncRequestPdu, SoftSyncTunnelType,
};
use ironrdp_dvc::{DrdynvcClient, DrdynvcServer};
use ironrdp_pdu::gcc::{ChannelName, ConnectionType, KeyboardType, RdpVersion};
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent, SynchronizeFlags};
use ironrdp_pdu::mcs::SendDataIndication;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::{
    self, CapabilitySet, MajorPlatformType, VirtualChannel, VirtualChannelFlags,
};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_pdu::rdp::headers::{ServerDeactivateAll, ShareControlHeader, ShareControlPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_svc::{
    SvcClientProcessor, SvcMessage, SvcProcessor, SvcServerProcessor, client_encode_svc_messages,
    client_encode_svc_messages_with_max_chunk_len, server_encode_svc_messages,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn line(name: &str, b: &[u8]) {
    println!("{name} {}", hex(b));
}

// A static channel that only makes the client ask for its name, or the
// server accept it.
macro_rules! named_channel {
    ($t:ident, $name:literal) => {
        #[derive(Debug)]
        struct $t;
        impl_as_any!($t);
        impl SvcProcessor for $t {
            fn channel_name(&self) -> ChannelName {
                ChannelName::from_utf8($name).unwrap()
            }
            fn process(&mut self, _: &[u8]) -> ironrdp_pdu::PduResult<Vec<SvcMessage>> {
                Ok(Vec::new())
            }
        }
        impl SvcClientProcessor for $t {}
        impl SvcServerProcessor for $t {}
    };
}

named_channel!(Cliprdr, "cliprdr");
named_channel!(Rdpdr, "rdpdr");
named_channel!(Rdpsnd, "rdpsnd");

#[allow(dead_code)]
fn _any(_: &dyn Any) {}

// The browser client's connector configuration (ironrdp-web build_config,
// non-legacy graphics), with fixed credentials.
fn client_config() -> Config {
    Config {
        credentials: Credentials::UsernamePassword {
            username: "user".to_owned(),
            password: "password".to_owned(),
        },
        domain: None,
        enable_tls: true,
        enable_credssp: false,
        enable_standard_rdp_security: false,
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        connection_type: ConnectionType::Lan,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width: 1280, height: 720 },
        monitor_layout: None,
        bitmap: None,
        client_build: 0,
        client_name: "localport".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNSPECIFIED,
        compression_type: None,
        enable_server_pointer: true,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        request_data: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
        rdp_version: RdpVersion::V5_PLUS,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: capability_sets::RailSupportLevel::SUPPORTED,
    }
}

// The server's capability sets of ironrdp-server (capabilities.rs) that the
// client needs, with the given Virtual Channel Capability Set.
fn server_capabilities(chunk_size: Option<u32>) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(capability_sets::General {
            extra_flags: capability_sets::GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(capability_sets::Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: 1280,
            desktop_height: 720,
            desktop_resize_flag: true,
            drawing_flags: capability_sets::BitmapDrawingFlags::empty(),
        }),
        CapabilitySet::Order(capability_sets::Order::new(
            capability_sets::OrderFlags::empty(),
            capability_sets::OrderSupportExFlags::empty(),
            2048,
            224,
        )),
        CapabilitySet::Pointer(capability_sets::Pointer {
            color_pointer_cache_size: 2048,
            pointer_cache_size: 2048,
        }),
        CapabilitySet::Input(capability_sets::Input {
            input_flags: capability_sets::InputFlags::SCANCODES
                | capability_sets::InputFlags::MOUSEX
                | capability_sets::InputFlags::FASTPATH_INPUT
                | capability_sets::InputFlags::UNICODE
                | capability_sets::InputFlags::FASTPATH_INPUT_2,
            keyboard_layout: 0,
            keyboard_type: None,
            keyboard_subtype: 0,
            keyboard_function_key: 128,
            keyboard_ime_filename: "".into(),
        }),
        CapabilitySet::VirtualChannel(VirtualChannel {
            flags: VirtualChannelFlags::NO_COMPRESSION,
            chunk_size,
        }),
        CapabilitySet::MultiFragmentUpdate(capability_sets::MultifragmentUpdate {
            max_request_size: 8 * 1024 * 1024,
        }),
    ]
}

#[derive(Clone, Copy)]
enum Channels {
    Base,
    DrdynvcOnly,
    CliprdrOnly,
    None,
    WithRdpdr,
}

struct Ids {
    user: u16,
    cliprdr: u16,
    drdynvc: u16,
}

// Feeds one side the PDUs the other wrote, one PDU per step as the driver of
// a real connection does, and records every write after the security upgrade.
fn session(variant: &str, channels: Channels, chunk_size: Option<u32>) -> Ids {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 33899));
    let mut client = ClientConnector::new(client_config(), addr);
    let mut server = Acceptor::new(
        SecurityProtocol::SSL,
        DesktopSize { width: 1280, height: 720 },
        server_capabilities(chunk_size),
        None,
    );
    match channels {
        Channels::Base => {
            client.attach_static_channel(Cliprdr);
            client.attach_static_channel(DrdynvcClient::new());
        }
        Channels::DrdynvcOnly => client.attach_static_channel(DrdynvcClient::new()),
        Channels::CliprdrOnly => client.attach_static_channel(Cliprdr),
        Channels::None => {}
        Channels::WithRdpdr => {
            client.attach_static_channel(Cliprdr);
            client.attach_static_channel(DrdynvcClient::new());
            client.attach_static_channel(Rdpsnd);
            client.attach_static_channel(Rdpdr);
        }
    }
    server.attach_static_channel(Cliprdr);
    server.attach_static_channel(DrdynvcServer::new());
    server.attach_static_channel(Rdpsnd);
    server.attach_static_channel(Rdpdr);

    let (mut to_server, mut to_client) = (Vec::<u8>::new(), Vec::<u8>::new());
    let (mut client_up, mut server_up) = (false, false);
    let mut n = 0;
    for _ in 0..10_000 {
        if client.should_perform_security_upgrade() {
            client.mark_security_upgrade_as_done();
            client_up = true;
        }
        if server.reached_security_upgrade().is_some() {
            server.mark_security_upgrade_as_done();
            server_up = true;
        }
        let client_done = client.state().is_terminal();
        let server_done = server.state().is_terminal();
        if client_done && server_done {
            break;
        }
        let recording = client_up && server_up;
        let mut progressed = false;
        if !client_done {
            if let Some(out) = step(&mut client, &mut to_client) {
                if recording && !out.is_empty() {
                    line(&format!("{variant}.{n:02}.c"), &out);
                    n += 1;
                }
                to_server.extend_from_slice(&out);
                progressed = true;
            }
        }
        if !server_done {
            if let Some(out) = step(&mut server, &mut to_server) {
                if recording && !out.is_empty() {
                    line(&format!("{variant}.{n:02}.s"), &out);
                    n += 1;
                }
                to_client.extend_from_slice(&out);
                progressed = true;
            }
        }
        if !progressed && !(client.should_perform_security_upgrade() || server.reached_security_upgrade().is_some())
        {
            panic!("{variant}: no progress");
        }
    }
    let result = server.get_result().expect("accepted");
    Ids {
        user: result.user_channel_id,
        cliprdr: result.static_channels.get_channel_id_by_type::<Cliprdr>().unwrap_or(0),
        drdynvc: result.static_channels.get_channel_id_by_type::<DrdynvcServer>().unwrap_or(0),
    }
}

// One step of seq: the next whole PDU from inbox when it waits for one, or a
// step without input. None when it waits for bytes not written yet.
fn step(seq: &mut dyn Sequence, inbox: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut out = WriteBuf::new();
    match seq.next_pdu_hint() {
        None => {
            seq.step_no_input(&mut out).expect("step");
        }
        Some(hint) => {
            let (_, size) = hint.find_size(inbox).expect("pdu size")?;
            let pdu: Vec<u8> = inbox.drain(..size).collect();
            seq.step(&pdu, None, &mut out).expect("step");
        }
    }
    Some(out.filled().to_vec())
}

fn clip(pdu: ClipboardPdu<'static>) -> Vec<SvcMessage> {
    vec![SvcMessage::from(pdu)]
}

fn main() {
    let ids = session("base", Channels::Base, None);
    session("chunk", Channels::Base, Some(4096));
    session("drdynvc", Channels::DrdynvcOnly, None);
    session("cliprdr", Channels::CliprdrOnly, None);
    session("none", Channels::None, None);
    session("rdpdr", Channels::WithRdpdr, None);
    line("ids", &[ids.user.to_be_bytes(), ids.cliprdr.to_be_bytes(), ids.drdynvc.to_be_bytes()].concat());

    let c = |name: &str, m: Vec<SvcMessage>| {
        line(name, &client_encode_svc_messages(m, ids.cliprdr, ids.user).unwrap());
    };
    let s = |name: &str, m: Vec<SvcMessage>| {
        line(name, &server_encode_svc_messages(m, ids.cliprdr, ids.user).unwrap());
    };

    let all_flags = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
        | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
        | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
        | ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA
        | ClipboardGeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED;
    let long = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES;
    let caps = |f| ClipboardPdu::Capabilities(Capabilities::new(ClipboardProtocolVersion::V2, f));
    s("s.caps", clip(caps(all_flags)));
    s("s.caps_cleared", clip(caps(long)));
    s("s.caps_short", clip(caps(ClipboardGeneralCapabilityFlags::empty())));
    c("c.caps", clip(caps(all_flags)));
    c("c.caps_cleared", clip(caps(long)));
    c("c.caps_short", clip(caps(ClipboardGeneralCapabilityFlags::empty())));
    s("s.monitor_ready", clip(ClipboardPdu::MonitorReady));
    c("c.monitor_ready", clip(ClipboardPdu::MonitorReady));
    c(
        "c.temp_dir",
        clip(ClipboardPdu::TemporaryDirectory(ClientTemporaryDirectory::new("C:\\Temp").unwrap())),
    );

    let fmt = |id: u32| ClipboardFormat::new(ClipboardFormatId(id));
    let named = |id: u32, name: &'static str| fmt(id).with_name(ClipboardFormatName::new(name));
    let mixed = [
        fmt(13),
        fmt(1),
        fmt(16),
        fmt(8),
        named(0xC00E, "HTML Format"),
        named(0xC00F, "FileGroupDescriptorW"),
    ];
    let text = [fmt(13), fmt(1), fmt(16)];
    let list = |formats: &[ClipboardFormat], use_long| {
        ClipboardPdu::FormatList(FormatList::new_unicode(formats, use_long).unwrap())
    };
    for (side, enc) in [("s", &s as &dyn Fn(&str, Vec<SvcMessage>)), ("c", &c)] {
        enc(&format!("{side}.list_mixed_long"), clip(list(&mixed, true)));
        enc(&format!("{side}.list_text_long"), clip(list(&text, true)));
        // Short names hold 32 bytes, too few for these names in UTF-16.
        let ascii = |formats: &[ClipboardFormat]| {
            ClipboardPdu::FormatList(FormatList::new_ascii(formats, false).unwrap())
        };
        enc(&format!("{side}.list_mixed_short"), clip(ascii(&mixed)));
        enc(&format!("{side}.list_text_short"), clip(ascii(&text)));
        enc(&format!("{side}.list_image_long"), clip(list(&[fmt(8)], true)));
        enc(&format!("{side}.list_empty_long"), clip(list(&[], true)));
        enc(&format!("{side}.list_empty_short"), clip(list(&[], false)));
        enc(&format!("{side}.list_ok"), clip(ClipboardPdu::FormatListResponse(FormatListResponse::Ok)));
        enc(&format!("{side}.list_fail"), clip(ClipboardPdu::FormatListResponse(FormatListResponse::Fail)));
        let req = |id| ClipboardPdu::FormatDataRequest(FormatDataRequest { format: ClipboardFormatId(id) });
        enc(&format!("{side}.req_unicode"), clip(req(13)));
        enc(&format!("{side}.req_text"), clip(req(1)));
        enc(&format!("{side}.req_html"), clip(req(0xC00E)));
        enc(&format!("{side}.req_dib"), clip(req(8)));
        let text: Vec<u8> = "copied text\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        enc(
            &format!("{side}.resp_text"),
            clip(ClipboardPdu::FormatDataResponse(FormatDataResponse::new_data(text))),
        );
        enc(
            &format!("{side}.resp_fail"),
            clip(ClipboardPdu::FormatDataResponse(FormatDataResponse::new_error())),
        );
        enc(
            &format!("{side}.resp_4000"),
            clip(ClipboardPdu::FormatDataResponse(FormatDataResponse::new_data(vec![0x41u8; 4000]))),
        );
        enc(
            &format!("{side}.filecontents_req"),
            clip(ClipboardPdu::FileContentsRequest(FileContentsRequest {
                stream_id: 7,
                index: 0,
                flags: FileContentsFlags::RANGE,
                position: 0,
                requested_size: 1024,
                data_id: None,
            })),
        );
        enc(
            &format!("{side}.filecontents_fail"),
            clip(ClipboardPdu::FileContentsResponse(FileContentsResponse::new_error(7))),
        );
        enc(
            &format!("{side}.filecontents_data"),
            clip(ClipboardPdu::FileContentsResponse(FileContentsResponse::new_data_response(
                7,
                Cow::Owned(vec![1, 2, 3]),
            ))),
        );
        enc(&format!("{side}.lock"), clip(ClipboardPdu::LockData(LockDataId(3))));
        enc(&format!("{side}.unlock"), clip(ClipboardPdu::UnlockData(LockDataId(3))));
    }
    line(
        "c.resp_4000_chunk4096",
        &client_encode_svc_messages_with_max_chunk_len(
            clip(ClipboardPdu::FormatDataResponse(FormatDataResponse::new_data(vec![0x41u8; 4000]))),
            ids.cliprdr,
            ids.user,
            4096,
        )
        .unwrap(),
    );

    let dc = |name: &str, pdu: DrdynvcClientPdu| {
        line(name, &client_encode_svc_messages(vec![SvcMessage::from(pdu)], ids.drdynvc, ids.user).unwrap());
    };
    let ds = |name: &str, pdu: DrdynvcServerPdu| {
        line(name, &server_encode_svc_messages(vec![SvcMessage::from(pdu)], ids.drdynvc, ids.user).unwrap());
    };
    const DISPLAY: &str = "Microsoft::Windows::RDS::DisplayControl";
    ds("s.dvc_caps_v1", DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V1, None)));
    ds("s.dvc_caps_v2", DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V2, Some([0; 4]))));
    ds("s.dvc_caps_v3", DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V3, Some([0; 4]))));
    dc("c.dvc_caps_rsp_v1", DrdynvcClientPdu::Capabilities(CapabilitiesResponsePdu::new(CapsVersion::V1)));
    dc("c.dvc_caps_rsp_v2", DrdynvcClientPdu::Capabilities(CapabilitiesResponsePdu::new(CapsVersion::V2)));
    dc("c.dvc_caps_rsp_v3", DrdynvcClientPdu::Capabilities(CapabilitiesResponsePdu::new(CapsVersion::V3)));
    ds("s.dvc_create_display", DrdynvcServerPdu::Create(CreateRequestPdu::new(3, DISPLAY.to_owned())));
    ds(
        "s.dvc_create_gfx",
        DrdynvcServerPdu::Create(CreateRequestPdu::new(4, "Microsoft::Windows::RDS::Graphics".to_owned())),
    );
    ds("s.dvc_create_display_wide", DrdynvcServerPdu::Create(CreateRequestPdu::new(70_000, DISPLAY.to_owned())));
    dc("c.dvc_create_ok", DrdynvcClientPdu::Create(CreateResponsePdu::new(3, CreationStatus::OK)));
    dc("c.dvc_create_fail", DrdynvcClientPdu::Create(CreateResponsePdu::new(3, CreationStatus::NOT_FOUND)));
    dc("c.dvc_create_gfx_not_found", DrdynvcClientPdu::Create(CreateResponsePdu::new(4, CreationStatus::NOT_FOUND)));
    dc("c.dvc_create_gfx_ok", DrdynvcClientPdu::Create(CreateResponsePdu::new(4, CreationStatus::OK)));
    let data = |id, b: &[u8]| DrdynvcDataPdu::Data(DataPdu::new(id, b.to_vec()));
    ds("s.dvc_data", DrdynvcServerPdu::Data(data(3, b"server display data")));
    dc("c.dvc_data", DrdynvcClientPdu::Data(data(3, b"client display data")));
    ds("s.dvc_data_gfx", DrdynvcServerPdu::Data(data(4, b"graphics")));
    dc("c.dvc_data_gfx", DrdynvcClientPdu::Data(data(4, b"graphics")));
    dc(
        "c.dvc_data_first",
        DrdynvcClientPdu::Data(DrdynvcDataPdu::DataFirst(DataFirstPdu::new(3, 3000, vec![0x42; 1500]))),
    );
    ds(
        "s.dvc_data_compressed",
        DrdynvcServerPdu::Data(DrdynvcDataPdu::DataCompressed(DataCompressedPdu::new(3, vec![0xE0, 0x04, 0x00]))),
    );
    dc(
        "c.dvc_data_compressed",
        DrdynvcClientPdu::Data(DrdynvcDataPdu::DataCompressed(DataCompressedPdu::new(3, vec![0xE0, 0x04, 0x00]))),
    );
    ds(
        "s.dvc_soft_sync",
        DrdynvcServerPdu::SoftSyncRequest(SoftSyncRequestPdu::new(vec![SoftSyncChannelList::new(
            SoftSyncTunnelType::RELIABLE_UDP,
            vec![3],
        )])),
    );
    ds("s.dvc_close", DrdynvcServerPdu::Close(ClosePdu::new(3)));
    dc("c.dvc_close", DrdynvcClientPdu::Close(ClosePdu::new(3)));
    ds("s.dvc_close_gfx", DrdynvcServerPdu::Close(ClosePdu::new(4)));

    let input = FastPathInput::new(vec![FastPathInputEvent::SyncEvent(SynchronizeFlags::empty())]).unwrap();
    line("c.fastpath_sync", &encode_vec(&input).unwrap());

    let deactivate = encode_vec(&ShareControlHeader {
        share_control_pdu: ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll),
        pdu_source: ids.user,
        share_id: 0,
    })
    .unwrap();
    let io = 1003;
    line(
        "s.deactivate_all",
        &encode_vec(&X224(SendDataIndication {
            initiator_id: ids.user,
            channel_id: io,
            user_data: Cow::Owned(deactivate),
        }))
        .unwrap(),
    );
}
