package database

// summaryWatermark is the stored watermark as the tests read it. Production
// reads it through summaryProgress, which reports a failed read; a test wants
// the value.
func (d *Database) summaryWatermark(interval string) int64 {
	return int64(d.GetIntSetting(flowSummaryWatermarkKeyPrefix+interval, 0))
}
