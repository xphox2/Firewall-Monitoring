# FortiGate SNMP Setup Guide

## Enable SNMP on FortiGate

### Via Web GUI

1. Log in to FortiGate web interface
2. Go to **System** > **SNMP**
3. Enable SNMP and configure:
   - **SNMP Version**: v2c (recommended for monitoring)
   - **Community**: public (or custom)
   - **Port**: 161

### Via CLI

```bash
config system snmp
    set status enable
    set community "public"
    set trap-high-cpu enable
    set trap-low-memory enable
    set trap-full-fortiview enable
end
```

## Configure SNMP Traps

### Via Web GUI

1. Go to **System** > **SNMP** > **SNMP Trap**
2. Configure trap receiver:
   - **IP Address**: Your monitoring server IP
   - **Port**: 162

### Via CLI

```bash
config system snmp
    config trapd
        edit 0
            set ip <your-server-ip>
            set port 162
        next
    end
end
```

## Required OIDs

### System Monitoring OIDs

| OID | Name | Description |
|-----|------|-------------|
| .1.3.6.1.4.1.12356.101.4.1.1 | fgSysVersion | Firmware version |
| .1.3.6.1.4.1.12356.101.4.1.2 | fgSysHostname | Hostname |
| .1.3.6.1.4.1.12356.101.4.1.3 | fgSysCpuUsage | CPU usage % |
| .1.3.6.1.4.1.12356.101.4.1.4 | fgSysMemUsage | Memory usage % |
| .1.3.6.1.4.1.12356.101.4.1.5 | fgSysMemCapacity | Total RAM (KB) |
| .1.3.6.1.4.1.12356.101.4.1.6 | fgSysDiskUsage | Disk usage (MB) |
| .1.3.6.1.4.1.12356.101.4.1.7 | fgSysDiskCapacity | Disk capacity (MB) |
| .1.3.6.1.4.1.12356.101.4.1.8 | fgSysSesCount | Active sessions |
| .1.3.6.1.4.1.12356.101.4.1.20 | fgSysUpTime | System uptime (1/100 sec) |

### Interface OIDs (RFC IF-MIB)

| OID | Name | Description |
|-----|------|-------------|
| .1.3.6.1.2.1.2.2.1.2 | ifDescr | Interface description |
| .1.3.6.1.2.1.2.2.1.5 | ifSpeed | Interface speed (bps) |
| .1.3.6.1.2.1.2.2.1.8 | ifOperStatus | Operational status |
| .1.3.6.1.2.1.2.2.1.10 | ifInOctets | Inbound bytes |
| .1.3.6.1.2.1.2.2.1.14 | ifInErrors | Inbound errors |
| .1.3.6.1.2.1.2.2.1.16 | ifInDiscards | Inbound discards |
| .1.3.6.1.2.1.2.2.1.17 | ifOutOctets | Outbound bytes |
| .1.3.6.1.2.1.2.2.1.20 | ifOutErrors | Outbound errors |
| .1.3.6.1.2.1.2.2.1.21 | ifOutDiscards | Outbound discards |

### Hardware Sensors OIDs

| OID | Name | Description |
|-----|------|-------------|
| .1.3.6.1.4.1.12356.101.4.3.1 | fgHwSensorCount | Number of sensors |
| .1.3.6.1.4.1.12356.101.4.3.2.1 | fgHwSensorTable | Sensor values |

### HA OIDs

| OID | Name | Description |
|-----|------|-------------|
| .1.3.6.1.4.1.12356.101.13.1.1 | fgHaMode | HA mode |
| .1.3.6.1.4.1.12356.101.13.1.2 | fgHaGroupName | Cluster name |
| .1.3.6.1.4.1.12356.101.13.1.3 | fgHaMasterIP | Master IP |
| .1.3.6.1.4.1.12356.101.13.1.4 | fgHaSlaveIP | Slave IP |

## Trap OIDs

| Trap OID | Name | Description |
|----------|------|-------------|
| .1.3.6.1.4.1.12356.101.2.0.301 | fgTrapVpnTunUp | VPN tunnel up |
| .1.3.6.1.4.1.12356.101.2.0.302 | fgTrapVpnTunDown | VPN tunnel down |
| .1.3.6.1.4.1.12356.101.2.0.401 | fgTrapHaSwitch | HA master failover |
| .1.3.6.1.4.1.12356.101.2.0.402 | fgTrapHaStateChange | HA state change |
| .1.3.6.1.4.1.12356.101.2.0.403 | fgTrapHaHBFail | HA heartbeat fail |
| .1.3.6.1.4.1.12356.101.2.0.503 | fgTrapIpsSignature | IPS signature triggered |
| .1.3.6.1.4.1.12356.101.2.0.601 | fgTrapAvVirus | Virus detected |

## Recommended Poll Intervals

To avoid overloading the FortiGate:

| Metric | Interval | Notes |
|--------|----------|-------|
| CPU/Memory/Disk | 60s | Lightweight |
| Sessions | 30-60s | Changes frequently |
| Interfaces | 60-120s | Depends on interface count |
| Hardware sensors | 300s | Slow-changing |
| Full system walk | 300s | Comprehensive |

## Test SNMP Connectivity

```bash
# Test SNMP get
snmpget -v 2c -c public 192.168.1.1 .1.3.6.1.4.1.12356.101.4.1.3

# Test SNMP walk
snmpwalk -v 2c -c public 192.168.1.1 .1.3.6.1.4.1.12356.101

# Test trap reception
snmptrap -v 2c -c public 192.168.1.1:162 '' .1.3.6.1.4.1.12356.101.2.0.401
```
