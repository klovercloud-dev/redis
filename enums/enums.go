package enums

import "time"

const (
	// REDIS PLUGIN NAME
	REDIS = "redis"
)

const (
	DefaultTtl     = 360
	ZoneUpdateTime = 10 * time.Minute
	TransferLength = 1000
)

type COMMAND_NAME string

const (
	// REDIS COMMAND NAME
	KEYS     = COMMAND_NAME("KEYS")
	HGET     = COMMAND_NAME("HGET")
	HSET     = COMMAND_NAME("HSET")
	HKEYS    = COMMAND_NAME("HKEYS")
	EVALUATE = COMMAND_NAME("EVAL")
)

type RECORD_TYPE string

const (
	// REDIS COMMAND NAME
	SIMPLE       = RECORD_TYPE("SIMPLE")
	FAIL_OVER    = RECORD_TYPE("HGET")
	GEO_LOCATION = RECORD_TYPE("GEO_LOCATION")
)
