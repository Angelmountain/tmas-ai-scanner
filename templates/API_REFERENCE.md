# Vision One API Reference (Search Endpoints)

Source: `sp-api-open-v3.0.json` and `sp-api-open-beta.json`

## Search Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v3.0/search/networkActivities` | GET | Network activity (NDR) data |
| `/v3.0/search/detections` | GET | Detection/alert data |
| `/v3.0/search/endpointActivities` | GET | Endpoint telemetry |
| `/v3.0/search/emailActivities` | GET | Email activity |
| `/v3.0/search/cloudActivities` | GET | Cloud (AWS CloudTrail/VPC) |
| `/v3.0/search/containerActivities` | GET | Container activity |
| `/v3.0/search/identityActivities` | GET | Identity/access activity |
| `/v3.0/search/mobileActivities` | GET | Mobile activity |
| `/v3.0/search/activityStatistics` | GET | Event counts per source |

## Common Parameters

| Parameter | Location | Type | Values |
|-----------|----------|------|--------|
| `TMV1-Query` | header | string | **Required**. Query filter |
| `startDateTime` | query | ISO 8601 | Default: 24h before request |
| `endDateTime` | query | ISO 8601 | Default: time of request |
| `top` | query | integer | **[50, 100, 500, 1000, 5000]**. Default: 500 |
| `mode` | query | string | **[default, countOnly, performance]**. Default: default |
| `select` | query | string | Comma-separated field names |

## Modes

- **`default`** - Returns records with pagination. `top` controls page size.
- **`countOnly`** - Returns only `{"totalCount": N}`. No records.
- **`performance`** - Ignores `top`. May return 0 records while progressRate < 100. Follow nextLink until done.

## Pagination

Response:
```json
{
  "nextLink": "https://api.xdr.trendmicro.com/v3.0/search/networkActivities?...&skipToken=...",
  "progressRate": 30,
  "items": [...]
}
```

- Follow `nextLink` URL to get next page (contains opaque `skipToken`)
- Keep fetching until `nextLink` is absent AND `progressRate` = 100
- **No skip/offset parameter** - forward-only pagination
- **Max 5000 records per page**

## TMV1-Query Fields: networkActivities

| Field | Match | Description |
|-------|-------|-------------|
| `suid` | Partial | Security user ID (account name) |
| `hostName` | Partial | HTTP Host / DNS domain |
| `app` | Partial | Application/protocol (HTTP, SSH, RDP) |
| `serverPort` | Full | Destination port |
| `clientIp` | Partial | Source IP |
| `serverIp` | Partial | Destination IP |
| `requestMethod` | Partial | HTTP method |
| `respCode` | Partial | HTTP response code |
| `sslCertCommonName` | Partial | SSL certificate CN |
| `fileName` | Partial | File name |
| `fileType` | Partial | File type |
| `request` | Partial | Request URL |
| `ruleName` | Partial | Detection rule name |
| `productCode` | Partial | Sensor type (pdi=NDR, xns=Network Sensor) |
| `tags` | Partial | Vision One tags |
| `flowId` | Partial | Flow identifier |
| `clientPort` | Full | Source port |
| `ja3Hash` | Partial | JA3 fingerprint |
| `ja3sHash` | Partial | JA3S fingerprint |

## TMV1-Query Fields: detections

| Field | Match | Description |
|-------|-------|-------------|
| `ruleName` | Partial | Detection rule |
| `suid` | Partial | User ID |
| `hostName` | Partial | Hostname |
| `tacticId` | Partial | MITRE tactic |
| `techniqueId` | Partial | MITRE technique |
| `filterRiskLevel` | Partial | Risk level |
| `productCode` | Partial | Sensor type |
| `eventName` | Partial | Event name |
| `fileName` | Partial | File name |
| `src` / `dst` | Partial | Source/dest IP |
| `tags` | Partial | Tags |

## Key Limitations

- **Max 5000 records per page, max ~10K per query window**
- **No server-side aggregation** (no groupBy, no count-by-field)
- **`field:*` does NOT filter to non-empty values** - it matches all records where the field exists in schema
- **Must use time chunking** to get complete data across large time windows
- **`countOnly` mode** can tell you how many records exist without fetching them

## API Rate Limits

- **Rate limit**: Max requests per 60 seconds. Exceeding returns **429 Too Many Requests**.
- **Request body**: Max 1 MB. Exceeding returns **413**.
- **Request timeout**: **60 seconds**. If processing takes longer, returns **504** (or 599 from some endpoints).

### Implications for our tool

- `top=1000` keeps page processing under 60s (was 5000 which caused timeouts)
- 0.5s delay between requests to stay under rate limit
- 15-min time chunks for dense data (>2K records/hour)
- `select` parameter reduces response size but not server processing time
- `mode=countOnly` is fast (no data processing) - use for probes
