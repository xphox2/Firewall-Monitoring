package normalize

import "strings"

// FortiGate writes geo as a country NAME (`srccountry="Netherlands"`), the
// spelling of the legacy MaxMind GeoIP database FortiOS ships; the typed
// columns hold ISO 3166-1 alpha-2 so every vendor compares equal. A name
// outside the table (or one of the non-country buckets — Reserved, Europe,
// Asia/Pacific Region, Anonymous Proxy, Satellite Provider) maps to "" and
// the raw name is kept in Extra[src_country_name|dst_country_name] so nothing
// is lost. The table is keyed case-insensitively.
var countryByName, countryByCode = func() (map[string]string, map[string]string) {
	byName := make(map[string]string, 260)
	byCode := make(map[string]string, 250)
	for _, line := range strings.Split(countryTable, "\n") {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			cc, name, _ := strings.Cut(pair, "=")
			byName[name] = cc
			byName[strings.ToLower(name)] = cc
			if _, dup := byCode[cc]; !dup { // first spelling listed is FortiOS's
				byCode[cc] = name
			}
		}
	}
	return byName, byCode
}()

// CountryCode returns the ISO2 code for a FortiGate country name, or "".
func CountryCode(name string) string {
	if name == "" {
		return ""
	}
	if cc, ok := countryByName[name]; ok { // exact spelling first: ToLower allocates
		return cc
	}
	if cc, ok := countryByName[strings.ToLower(name)]; ok {
		return cc
	}
	return ""
}

// CountryName is the inverse: the FortiOS spelling for an ISO2 code, or ""
// (deny.FromEvent re-creates the DeniedEvent country name from it).
func CountryName(cc string) string { return countryByCode[cc] }

// countryTable: `CC=Name;CC=Name…`. Names follow the legacy MaxMind spelling
// FortiOS uses (Russian Federation, Korea Republic of, Viet Nam, Taiwan …);
// a few common alternates are listed twice so both spellings resolve.
const countryTable = `
AD=Andorra;AE=United Arab Emirates;AF=Afghanistan;AG=Antigua and Barbuda;AI=Anguilla;AL=Albania;AM=Armenia;AO=Angola;AQ=Antarctica
AR=Argentina;AS=American Samoa;AT=Austria;AU=Australia;AW=Aruba;AX=Aland Islands;AZ=Azerbaijan;BA=Bosnia and Herzegovina;BB=Barbados
BD=Bangladesh;BE=Belgium;BF=Burkina Faso;BG=Bulgaria;BH=Bahrain;BI=Burundi;BJ=Benin;BL=Saint Barthelemy;BM=Bermuda;BN=Brunei Darussalam
BO=Bolivia;BQ=Bonaire, Saint Eustatius and Saba;BR=Brazil;BS=Bahamas;BT=Bhutan;BV=Bouvet Island;BW=Botswana;BY=Belarus;BZ=Belize
CA=Canada;CC=Cocos (Keeling) Islands;CD=Congo, The Democratic Republic of the;CF=Central African Republic;CG=Congo;CH=Switzerland
CI=Cote d'Ivoire;CK=Cook Islands;CL=Chile;CM=Cameroon;CN=China;CO=Colombia;CR=Costa Rica;CU=Cuba;CV=Cape Verde;CW=Curacao
CX=Christmas Island;CY=Cyprus;CZ=Czech Republic;CZ=Czechia;DE=Germany;DJ=Djibouti;DK=Denmark;DM=Dominica;DO=Dominican Republic
DZ=Algeria;EC=Ecuador;EE=Estonia;EG=Egypt;EH=Western Sahara;ER=Eritrea;ES=Spain;ET=Ethiopia;FI=Finland;FJ=Fiji
FK=Falkland Islands (Malvinas);FM=Micronesia, Federated States of;FO=Faroe Islands;FR=France;GA=Gabon;GB=United Kingdom;GD=Grenada
GE=Georgia;GF=French Guiana;GG=Guernsey;GH=Ghana;GI=Gibraltar;GL=Greenland;GM=Gambia;GN=Guinea;GP=Guadeloupe;GQ=Equatorial Guinea
GR=Greece;GS=South Georgia and the South Sandwich Islands;GT=Guatemala;GU=Guam;GW=Guinea-Bissau;GY=Guyana;HK=Hong Kong
HM=Heard Island and McDonald Islands;HN=Honduras;HR=Croatia;HT=Haiti;HU=Hungary;ID=Indonesia;IE=Ireland;IL=Israel;IM=Isle of Man
IN=India;IO=British Indian Ocean Territory;IQ=Iraq;IR=Iran, Islamic Republic of;IR=Iran;IS=Iceland;IT=Italy;JE=Jersey;JM=Jamaica
JO=Jordan;JP=Japan;KE=Kenya;KG=Kyrgyzstan;KH=Cambodia;KI=Kiribati;KM=Comoros;KN=Saint Kitts and Nevis
KP=Korea, Democratic People's Republic of;KR=Korea, Republic of;KR=South Korea;KW=Kuwait;KY=Cayman Islands;KZ=Kazakhstan
LA=Lao People's Democratic Republic;LB=Lebanon;LC=Saint Lucia;LI=Liechtenstein;LK=Sri Lanka;LR=Liberia;LS=Lesotho;LT=Lithuania
LU=Luxembourg;LV=Latvia;LY=Libya;LY=Libyan Arab Jamahiriya;MA=Morocco;MC=Monaco;MD=Moldova, Republic of;ME=Montenegro
MF=Saint Martin;MG=Madagascar;MH=Marshall Islands;MK=Macedonia;MK=North Macedonia;ML=Mali;MM=Myanmar;MN=Mongolia;MO=Macao;MO=Macau
MP=Northern Mariana Islands;MQ=Martinique;MR=Mauritania;MS=Montserrat;MT=Malta;MU=Mauritius;MV=Maldives;MW=Malawi;MX=Mexico
MY=Malaysia;MZ=Mozambique;NA=Namibia;NC=New Caledonia;NE=Niger;NF=Norfolk Island;NG=Nigeria;NI=Nicaragua;NL=Netherlands;NO=Norway
NP=Nepal;NR=Nauru;NU=Niue;NZ=New Zealand;OM=Oman;PA=Panama;PE=Peru;PF=French Polynesia;PG=Papua New Guinea;PH=Philippines
PK=Pakistan;PL=Poland;PM=Saint Pierre and Miquelon;PN=Pitcairn;PR=Puerto Rico;PS=Palestinian Territory;PT=Portugal;PW=Palau
PY=Paraguay;QA=Qatar;RE=Reunion;RO=Romania;RS=Serbia;RU=Russian Federation;RU=Russia;RW=Rwanda;SA=Saudi Arabia;SB=Solomon Islands
SC=Seychelles;SD=Sudan;SE=Sweden;SG=Singapore;SH=Saint Helena;SI=Slovenia;SJ=Svalbard and Jan Mayen;SK=Slovakia;SL=Sierra Leone
SM=San Marino;SN=Senegal;SO=Somalia;SR=Suriname;SS=South Sudan;ST=Sao Tome and Principe;SV=El Salvador;SX=Sint Maarten
SY=Syrian Arab Republic;SZ=Swaziland;SZ=Eswatini;TC=Turks and Caicos Islands;TD=Chad;TF=French Southern Territories;TG=Togo
TH=Thailand;TJ=Tajikistan;TK=Tokelau;TL=Timor-Leste;TM=Turkmenistan;TN=Tunisia;TO=Tonga;TR=Turkey;TT=Trinidad and Tobago;TV=Tuvalu
TW=Taiwan;TZ=Tanzania, United Republic of;UA=Ukraine;UG=Uganda;UM=United States Minor Outlying Islands;US=United States
UY=Uruguay;UZ=Uzbekistan;VA=Holy See (Vatican City State);VC=Saint Vincent and the Grenadines;VE=Venezuela;VG=Virgin Islands, British
VI=Virgin Islands, U.S.;VN=Vietnam;VN=Viet Nam;VU=Vanuatu;WF=Wallis and Futuna;WS=Samoa;YE=Yemen;YT=Mayotte;ZA=South Africa
ZM=Zambia;ZW=Zimbabwe
`
