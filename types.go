package redis

import "net"

type Zone struct {
	Name      string              `json:"name"`
	Locations map[string]struct{} `json:"locations"`
}

type Record struct {
	A     New_A_Record     `json:"a,omitempty"`
	AAAA  []AAAA_Record    `json:"aaaa,omitempty"`
	TXT   []TXT_Record     `json:"txt,omitempty"`
	CNAME New_CNAME_Record `json:"cname,omitempty"`
	NS    []NS_Record      `json:"ns,omitempty"`
	MX    []MX_Record      `json:"mx,omitempty"`
	SRV   []SRV_Record     `json:"srv,omitempty"`
	CAA   []CAA_Record     `json:"caa,omitempty"`
	SOA   SOA_Record       `json:"soa,omitempty"`
}

type A_Record struct {
	Ttl uint32 `json:"ttl,omitempty"`
	Ip  net.IP `json:"ip"`
}

type CNAME_Record struct {
	Ttl  uint32 `json:"ttl,omitempty"`
	Host string `json:"host"`
}

type New_A_Record struct {
	Type  string
	Value interface{}
}

type New_CNAME_Record struct {
	Type  string
	Value interface{}
}

type Simple_CNAME_Record struct {
	Value []CNAME_Record `json:"value"`
}

type FailOver_CNAME_Record struct {
	Primary   FailOver_CNAME_Data `json:"primary"`
	Secondary FailOver_CNAME_Data `json:"secondary"`
}

type FailOver_CNAME_Data struct {
	Data              []CNAME_Record            `json:"data"`
	IsHealthy         bool                      `json:"isHealthy"`
	HealthCheckConfig FailOverHealthCheckConfig `json:"healthCheckConfig"`
}

type Geo_Location struct {
	Location string
	Value    map[string][]A_Record
}

type Geo_Location_CNAME struct {
	Location string
	Value    map[string][]CNAME_Record
}

type General_A_Record struct {
	Value []A_Record
}

type FailOver_A_Record struct {
	Primary   FailOverData
	Secondary FailOverData
}

type FailOverData struct {
	Data              []A_Record
	IsHealthy         bool
	HealthCheckConfig FailOverHealthCheckConfig
}

type FailOverHealthCheckConfig struct {
	Type      string
	TargetIPs []string
	Port      string
	TargetUrl string
}

type AAAA_Record struct {
	Ttl uint32 `json:"ttl,omitempty"`
	Ip  net.IP `json:"ip"`
}

type TXT_Record struct {
	Ttl  uint32 `json:"ttl,omitempty"`
	Text string `json:"text"`
}

type NS_Record struct {
	Ttl  uint32 `json:"ttl,omitempty"`
	Host string `json:"host"`
}

type MX_Record struct {
	Ttl        uint32 `json:"ttl,omitempty"`
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}

type SRV_Record struct {
	Ttl      uint32 `json:"ttl,omitempty"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

type SOA_Record struct {
	Ttl     uint32 `json:"ttl,omitempty"`
	Ns      string `json:"ns"`
	MBox    string `json:"MBox"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTtl  uint32 `json:"minttl"`
}

type CAA_Record struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}
