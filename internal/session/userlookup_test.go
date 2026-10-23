package session

func testUser(login string, uid uint32) *userRecord {
	return &userRecord{Name: login, UID: uid, GID: uid, Groups: []uint32{uid}, Home: "/home/" + login, Shell: "/bin/sh"}
}
