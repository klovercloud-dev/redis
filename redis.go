package redis

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/klovercloud-dev/get-ip-region"

	redisCon "github.com/gomodule/redigo/redis"
)

type Redis struct {
	Next           plugin.Handler
	Pool           *redisCon.Pool
	redisAddress   string
	redisPassword  string
	connectTimeout int
	readTimeout    int
	keyPrefix      string
	keySuffix      string
	Ttl            uint32
	Zones          []string
	LastZoneUpdate time.Time
}

func (redis *Redis) LoadZones() {
	var (
		reply interface{}
		err   error
		zones []string
	)

	conn := redis.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return
	}
	defer conn.Close()

	reply, err = conn.Do("KEYS", redis.keyPrefix+"*"+redis.keySuffix)
	if err != nil {
		return
	}
	zones, err = redisCon.Strings(reply, nil)
	for i, _ := range zones {
		zones[i] = strings.TrimPrefix(zones[i], redis.keyPrefix)
		zones[i] = strings.TrimSuffix(zones[i], redis.keySuffix)
	}
	redis.LastZoneUpdate = time.Now()
	redis.Zones = zones
}

func (redis *Redis) A(name string, z *Zone, record *Record, w dns.ResponseWriter) (answers, extras []dns.RR) {
	if record.A.Type == "SIMPLE" {
		valueBytes, _ := json.Marshal(record.A)

		aGeneral := General_A_Record{}
		fmt.Println("---------")
		fmt.Println(string(valueBytes))
		err := json.Unmarshal(valueBytes, &aGeneral)
		if err != nil {
			fmt.Println("this error")
			fmt.Println(err.Error())
		}

		for _, a := range aGeneral.Value {
			fmt.Println(a.Ip)
			if a.Ip == nil {
				continue
			}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: redis.minTtl(a.Ttl)}
			r.A = a.Ip
			answers = append(answers, r)
		}
		return
	} else if record.A.Type == "FAIL_OVER" {
		valueBytes, _ := json.Marshal(record.A.Value)

		aFailOver := FailOver_A_Record{}
		fmt.Println("---------")
		fmt.Println(record)
		err := json.Unmarshal(valueBytes, &aFailOver)
		if err != nil {
			fmt.Println("this error")
			fmt.Println(err.Error())
		}

		data := &aFailOver.Primary.Data
		if !aFailOver.Primary.IsHealthy {
			data = &aFailOver.Secondary.Data
		}

		for _, a := range *data {
			fmt.Println(a.Ip)
			if a.Ip == nil {
				continue
			}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: redis.minTtl(a.Ttl)}
			r.A = a.Ip
			answers = append(answers, r)
		}
		return
	} else if record.A.Type == "GEO_LOCATION" {
		valueBytes, _ := json.Marshal(record.A.Value)
		geo := Geo_Location{}
		json.Unmarshal(valueBytes, &geo)

		fmt.Println("ip : ", w.RemoteAddr())

		//BD
		//clientLocation := ipLocationService.GetCountry(net.ParseIP("113.21.230.206"))
		//US
		//clientLocation := ipLocationService.GetCountry(net.ParseIP("5.10.232.0"))
		//AU
		clientLocation := ipLocationService.GetCountry(net.ParseIP("1.0.4.0"))

		fmt.Println("Server Found Country: ", clientLocation)

		if geo.Value[clientLocation] == nil {
			clientLocation = "default"
		}

		fmt.Println("client loaction: ", clientLocation)

		for _, a := range geo.Value[clientLocation] {
			fmt.Println(a.Ip)
			if a.Ip == nil {
				continue
			}
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: redis.minTtl(a.Ttl)}
			r.A = a.Ip
			answers = append(answers, r)
		}
		return
	}
	return
}

func (redis Redis) AAAA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, aaaa := range record.AAAA {
		if aaaa.Ip == nil {
			continue
		}
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: redis.minTtl(aaaa.Ttl)}
		r.AAAA = aaaa.Ip
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) CNAME(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	fmt.Println("outside simple")
	if record.CNAME.Type == "SIMPLE" {
		fmt.Println("indise simple")
		valueBytes, _ := json.Marshal(record.CNAME)

		cnameGeneral := Simple_CNAME_Record{}
		fmt.Println("---------")
		fmt.Println(string(valueBytes))
		err := json.Unmarshal(valueBytes, &cnameGeneral)
		fmt.Println(cnameGeneral)
		if err != nil {
			fmt.Println("this error")
			fmt.Println(err.Error())
		}

		for _, cname := range cnameGeneral.Value {
			if len(cname.Host) == 0 {
				continue
			}
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: redis.minTtl(cname.Ttl)}
			r.Target = dns.Fqdn(cname.Host)
			fmt.Println("cname host: ", cname.Host)
			answers = append(answers, r)
		}
		return
	} else if record.CNAME.Type == "FAIL_OVER" {
		valueBytes, _ := json.Marshal(record.CNAME.Value)

		cnameFailOver := FailOver_CNAME_Record{}
		fmt.Println("---------")
		fmt.Println(record)
		err := json.Unmarshal(valueBytes, &cnameFailOver)
		if err != nil {
			fmt.Println("this error")
			fmt.Println(err.Error())
		}

		data := &cnameFailOver.Primary.Data
		if !cnameFailOver.Primary.IsHealthy {
			data = &cnameFailOver.Secondary.Data
		}

		for _, cname := range *data {
			if len(cname.Host) == 0 {
				continue
			}
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: redis.minTtl(cname.Ttl)}
			r.Target = dns.Fqdn(cname.Host)
			answers = append(answers, r)
		}
		return
	} else if record.CNAME.Type == "GEO_LOCATION" {
		valueBytes, _ := json.Marshal(record.CNAME.Value)
		geo_cname := Geo_Location_CNAME{}
		json.Unmarshal(valueBytes, &geo_cname)

		//fmt.Println("ip : ", w.RemoteAddr())

		//BD
		//clientLocation := ipLocationService.GetCountry(net.ParseIP("113.21.230.206"))
		//US
		clientLocation := ipLocationService.GetCountry(net.ParseIP("5.10.232.0"))
		//AU
		//clientLocation := ipLocationService.GetCountry(net.ParseIP("1.0.4.0"))

		fmt.Println("Server Found Country: ", clientLocation)

		if geo_cname.Value[clientLocation] == nil {
			clientLocation = "default"
		}

		fmt.Println("client loaction: ", clientLocation)

		//for _, a := range geo.Value[clientLocation] {
		//	fmt.Println(a.Ip)
		//	if a.Ip == nil {
		//		continue
		//	}
		//	r := new(dns.A)
		//	r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
		//		Class: dns.ClassINET, Ttl: redis.minTtl(a.Ttl)}
		//	r.A = a.Ip
		//	answers = append(answers, r)
		//}

		for _, cname := range geo_cname.Value[clientLocation] {
			if len(cname.Host) == 0 {
				continue
			}
			r := new(dns.CNAME)
			r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
				Class: dns.ClassINET, Ttl: redis.minTtl(cname.Ttl)}
			r.Target = dns.Fqdn(cname.Host)
			answers = append(answers, r)
		}
		return
	}

	//for _, cname := range record.CNAME {
	//	if len(cname.Host) == 0 {
	//		continue
	//	}
	//	r := new(dns.CNAME)
	//	r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
	//		Class: dns.ClassINET, Ttl: redis.minTtl(cname.Ttl)}
	//	r.Target = dns.Fqdn(cname.Host)
	//	answers = append(answers, r)
	//}
	return
}

func (redis *Redis) TXT(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, txt := range record.TXT {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: redis.minTtl(txt.Ttl)}
		r.Txt = split255(txt.Text)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) NS(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, ns := range record.NS {
		if len(ns.Host) == 0 {
			continue
		}
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: redis.minTtl(ns.Ttl)}
		r.Ns = ns.Host
		answers = append(answers, r)
		extras = append(extras, redis.hosts(ns.Host, z)...)
	}
	return
}

func (redis *Redis) MX(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, mx := range record.MX {
		if len(mx.Host) == 0 {
			continue
		}
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: redis.minTtl(mx.Ttl)}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
		extras = append(extras, redis.hosts(mx.Host, z)...)
	}
	return
}

func (redis *Redis) SRV(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	for _, srv := range record.SRV {
		if len(srv.Target) == 0 {
			continue
		}
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSRV,
			Class: dns.ClassINET, Ttl: redis.minTtl(srv.Ttl)}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
		extras = append(extras, redis.hosts(srv.Target, z)...)
	}
	return
}

func (redis *Redis) SOA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	r := new(dns.SOA)
	if record.SOA.Ns == "" {
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: redis.Ttl}
		r.Ns = "ns1." + name
		r.Mbox = "hostmaster." + name
		r.Refresh = 86400
		r.Retry = 7200
		r.Expire = 3600
		r.Minttl = redis.Ttl
	} else {
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(z.Name), Rrtype: dns.TypeSOA,
			Class: dns.ClassINET, Ttl: redis.minTtl(record.SOA.Ttl)}
		r.Ns = record.SOA.Ns
		r.Mbox = record.SOA.MBox
		r.Refresh = record.SOA.Refresh
		r.Retry = record.SOA.Retry
		r.Expire = record.SOA.Expire
		r.Minttl = record.SOA.MinTtl
	}
	r.Serial = redis.serial()
	answers = append(answers, r)
	return
}

func (redis *Redis) CAA(name string, z *Zone, record *Record) (answers, extras []dns.RR) {
	if record == nil {
		return
	}
	for _, caa := range record.CAA {
		if caa.Value == "" || caa.Tag == "" {
			continue
		}
		r := new(dns.CAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCAA, Class: dns.ClassINET}
		r.Flag = caa.Flag
		r.Tag = caa.Tag
		r.Value = caa.Value
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) AXFR(z *Zone) (records []dns.RR) {
	//soa, _ := redis.SOA(z.Name, z, record)
	soa := make([]dns.RR, 0)
	answers := make([]dns.RR, 0, 10)
	extras := make([]dns.RR, 0, 10)

	// Allocate slices for rr Records
	records = append(records, soa...)
	for key := range z.Locations {
		if key == "@" {
			location := redis.findLocation(z.Name, z)
			record := redis.get(location, z)
			soa, _ = redis.SOA(z.Name, z, record)
		} else {
			fqdnKey := dns.Fqdn(key) + z.Name
			var as []dns.RR
			var xs []dns.RR

			location := redis.findLocation(fqdnKey, z)
			record := redis.get(location, z)

			// Pull all zone records
			as, xs = redis.A(fqdnKey, z, record, nil)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = redis.AAAA(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = redis.CNAME(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = redis.MX(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = redis.SRV(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)

			as, xs = redis.TXT(fqdnKey, z, record)
			answers = append(answers, as...)
			extras = append(extras, xs...)
		}
	}

	records = soa
	records = append(records, answers...)
	records = append(records, extras...)
	records = append(records, soa...)

	fmt.Println(records)
	return
}

func (redis *Redis) hosts(name string, z *Zone) []dns.RR {
	var (
		record  *Record
		answers []dns.RR
	)
	location := redis.findLocation(name, z)
	if location == "" {
		return nil
	}
	record = redis.get(location, z)
	a, _ := redis.A(name, z, record, nil)
	answers = append(answers, a...)
	aaaa, _ := redis.AAAA(name, z, record)
	answers = append(answers, aaaa...)
	cname, _ := redis.CNAME(name, z, record)
	answers = append(answers, cname...)
	return answers
}

func (redis *Redis) serial() uint32 {
	return uint32(time.Now().Unix())
}

func (redis *Redis) minTtl(ttl uint32) uint32 {
	if redis.Ttl == 0 && ttl == 0 {
		return defaultTtl
	}
	if redis.Ttl == 0 {
		return ttl
	}
	if ttl == 0 {
		return redis.Ttl
	}
	if redis.Ttl < ttl {
		return redis.Ttl
	}
	return ttl
}

func (redis *Redis) findLocation(query string, z *Zone) string {
	var (
		ok                                 bool
		closestEncloser, sourceOfSynthesis string
	)

	// request for zone records
	if query == z.Name {
		return query
	}

	query = strings.TrimSuffix(query, "."+z.Name)

	if _, ok = z.Locations[query]; ok {
		return query
	}

	closestEncloser, sourceOfSynthesis, ok = splitQuery(query)
	for ok {
		ceExists := keyMatches(closestEncloser, z) || keyExists(closestEncloser, z)
		ssExists := keyExists(sourceOfSynthesis, z)
		if ceExists {
			if ssExists {
				return sourceOfSynthesis
			} else {
				return ""
			}
		} else {
			closestEncloser, sourceOfSynthesis, ok = splitQuery(closestEncloser)
		}
	}
	return ""
}

func (redis *Redis) get(key string, z *Zone) *Record {
	var (
		err   error
		reply interface{}
		val   string
	)
	conn := redis.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	var label string
	if key == z.Name {
		label = "@"
	} else {
		label = key
	}

	reply, err = conn.Do("HGET", redis.keyPrefix+z.Name+redis.keySuffix, label)
	if err != nil {
		return nil
	}
	val, err = redisCon.String(reply, nil)
	if err != nil {
		return nil
	}
	r := new(Record)

	fmt.Println(val)

	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		fmt.Println("error here.....")
		fmt.Println("parse error : ", val, err)
		return nil
	}
	return r
}

func keyExists(key string, z *Zone) bool {
	_, ok := z.Locations[key]
	return ok
}

func keyMatches(key string, z *Zone) bool {
	for value := range z.Locations {
		if strings.HasSuffix(value, key) {
			return true
		}
	}
	return false
}

func splitQuery(query string) (string, string, bool) {
	if query == "" {
		return "", "", false
	}
	var (
		splits            []string
		closestEncloser   string
		sourceOfSynthesis string
	)
	splits = strings.SplitAfterN(query, ".", 2)
	if len(splits) == 2 {
		closestEncloser = splits[1]
		sourceOfSynthesis = "*." + closestEncloser
	} else {
		closestEncloser = ""
		sourceOfSynthesis = "*"
	}
	return closestEncloser, sourceOfSynthesis, true
}

func (redis *Redis) Connect() {
	redis.Pool = &redisCon.Pool{
		Dial: func() (redisCon.Conn, error) {
			opts := []redisCon.DialOption{}
			if redis.redisPassword != "" {
				opts = append(opts, redisCon.DialPassword(redis.redisPassword))
			}
			if redis.connectTimeout != 0 {
				opts = append(opts, redisCon.DialConnectTimeout(time.Duration(redis.connectTimeout)*time.Millisecond))
			}
			if redis.readTimeout != 0 {
				opts = append(opts, redisCon.DialReadTimeout(time.Duration(redis.readTimeout)*time.Millisecond))
			}

			return redisCon.Dial("tcp", redis.redisAddress, opts...)
		},
	}
}

func (redis *Redis) save(zone string, subdomain string, value string) error {
	var err error

	conn := redis.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	_, err = conn.Do("HSET", redis.keyPrefix+zone+redis.keySuffix, subdomain, value)
	return err
}

func (redis *Redis) load(zone string) *Zone {
	var (
		reply interface{}
		err   error
		vals  []string
	)

	conn := redis.Pool.Get()
	if conn == nil {
		fmt.Println("error connecting to redis")
		return nil
	}
	defer conn.Close()

	reply, err = conn.Do("HKEYS", redis.keyPrefix+zone+redis.keySuffix)
	if err != nil {
		return nil
	}
	z := new(Zone)
	z.Name = zone
	vals, err = redisCon.Strings(reply, nil)
	if err != nil {
		return nil
	}
	z.Locations = make(map[string]struct{})
	for _, val := range vals {
		z.Locations[val] = struct{}{}
	}

	return z
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	sx := []string{}
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}

const (
	defaultTtl     = 360
	hostmaster     = "hostmaster"
	zoneUpdateTime = 10 * time.Minute
	transferLength = 1000
)
