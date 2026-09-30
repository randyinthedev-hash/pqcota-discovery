package network

// Handshake — 하나의 핸드셰이크 관측 결과(파싱 산출). 복호화 없이 평문에서 뽑는 협상 정보만 담는다.
// 등급은 여기 없다 — 코어가 NegotiatedGroup에서 파생한다(§1.2).
type Handshake struct {
	Protocol        string   // "TLS" | "SSH"
	Role            string   // "client"(ClientHello/클라이언트 KEXINIT) | "server"(ServerHello)
	Version         string   // "TLS1.3" 등 (관측 가능할 때)
	Cipher          string   // 선택된 cipher suite (ServerHello) 또는 ""
	NegotiatedGroup string   // 실제 선택된 KEX 그룹(ServerHello key_share) 또는 관측된 최선호(client)
	OfferedGroups   []string // 후보 그룹(ClientHello supported_groups / SSH kex 목록)
}
