// Prints, one per line as `<name> <hex DER>`, an RDCleanPath response, a
// negotiation error and a request encoded by ironrdp-rdcleanpath; the rdp
// gateway tests (rdpgateway_test.go) compare the agent's PDUs with them.
use ironrdp_rdcleanpath::RDCleanPathPdu;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let confirm = vec![0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00];
    let chain = vec![b"leaf-certificate-der".to_vec(), b"issuer-der".to_vec()];
    let resp = RDCleanPathPdu::new_response("192.168.1.20:3389".to_owned(), confirm.clone(), chain).unwrap();
    println!("response {}", hex(&resp.to_der().unwrap()));
    let nerr = RDCleanPathPdu::new_negotiation_error(confirm).unwrap();
    println!("negotiation_error {}", hex(&nerr.to_der().unwrap()));
    let req = RDCleanPathPdu::new_request(vec![0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00], "localport-desktop".to_owned(), "localport".to_owned(), None).unwrap();
    println!("request {}", hex(&req.to_der().unwrap()));
}
