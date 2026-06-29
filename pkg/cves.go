package pkg

var Projects = map[string]Output{
	"geolocation": {
		Slug: "geolocation",
		ProjectName: "Geolocation Field 8.x-3.15",
		ProjectURL: "https://www.drupal.org/project/geolocation/releases/8.x-3.15",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13242",
				Versions: "<3.15.0",
				Criticality: "Critical 19\u2009∕\u200925 AC:Basic/A:None/CI:All/II:All/E:Theoretical/TD:Default",
				Vulnerability: "SQL Injection",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-062",
			},
		},
	},
	"paragraphs": {
		Slug: "paragraphs",
		ProjectName: "Paragraphs 8.x-1.21",
		ProjectURL: "https://www.drupal.org/project/paragraphs/releases/8.x-1.21",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13241",
				Versions: "<1.21.0",
				Criticality: "Moderately critical 11\u2009∕\u200925 AC:Basic/A:None/CI:None/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-061",
			},
			{
				CVE: "CVE-2026-13240",
				Versions: "<1.21.0",
				Criticality: "Less critical 9\u2009∕\u200925 AC:Basic/A:User/CI:Some/II:None/E:Theoretical/TD:Uncommon",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-060",
			},
		},
	},
	"commerce_realex": {
		Slug: "commerce_realex",
		ProjectName: "commerce_realex  3.0.2",
		ProjectURL: "https://www.drupal.org/project/commerce_realex/releases/3.0.2",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13238",
				Versions: "<3.0.2",
				Criticality: "Moderately critical 12\u2009∕\u200925 AC:Basic/A:None/CI:None/II:Some/E:Theoretical/TD:Default",
				Vulnerability: "Access Bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-058",
			},
		},
	},
	"ai_agents": {
		Slug: "ai_agents",
		ProjectName: "AI Agents 1.3.1",
		ProjectURL: "https://www.drupal.org/project/ai_agents/releases/1.3.1",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13237",
				Versions: "<1.1.4 || >=1.2.0 <1.2.5 || >=1.3.0 <1.3.1",
				Criticality: "Moderately critical 13\u2009∕\u200925 AC:Complex/A:None/CI:Some/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Information disclosure, Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-057",
			},
			{
				CVE: "CVE-2026-13236",
				Versions: "<1.1.4 || >=1.2.0 <1.2.5 || >=1.3.0 <1.3.1",
				Criticality: "Less critical 9\u2009∕\u200925 AC:Basic/A:User/CI:Some/II:None/E:Theoretical/TD:Uncommon",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-056",
			},
		},
	},
	"admin_feedback": {
		Slug: "admin_feedback",
		ProjectName: "admin_feedback 8.x-2.8",
		ProjectURL: "https://www.drupal.org/project/admin_feedback/releases/8.x-2.8",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13232",
				Versions: "<2.8.0",
				Criticality: "Moderately critical 11\u2009∕\u200925 AC:Basic/A:User/CI:None/II:Some/E:Theoretical/TD:All",
				Vulnerability: "Access bypass / Insecure Direct Object Reference (IDOR)",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-052",
			},
			{
				CVE: "CVE-2026-13231",
				Versions: "<2.8.0",
				Criticality: "Moderately critical 13\u2009∕\u200925 AC:Basic/A:Admin/CI:Some/II:Some/E:Theoretical/TD:All",
				Vulnerability: "Cross-site scripting",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-051",
			},
		},
	},
	"plotly_js": {
		Slug: "plotly_js",
		ProjectName: "plotly_js-3.0.2",
		ProjectURL: "https://www.drupal.org/project/plotly_js/releases/3.0.2",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-55810",
				Versions: "<3.0.2",
				Criticality: "Critical 19\u2009∕\u200925 AC:None/A:User/CI:All/II:All/E:Theoretical/TD:Default",
				Vulnerability: "PHP object injection",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-050",
			},
		},
	},
	"tealiumiq": {
		Slug: "tealiumiq",
		ProjectName: "Tealium iQ Tag Management 8.x.2.4",
		ProjectURL: "https://www.drupal.org/project/tealiumiq/releases/8.x-2.4",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13244",
				Versions: "<2.4.0",
				Criticality: "Critical 19\u2009∕\u200925 AC:None/A:User/CI:All/II:All/E:Theoretical/TD:Default",
				Vulnerability: "PHP object injection",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-064",
			},
		},
	},
	"salesforce": {
		Slug: "salesforce",
		ProjectName: "Salesforce Suite version 5.1.3",
		ProjectURL: "https://www.drupal.org/project/salesforce/releases/5.1.3",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13243",
				Versions: "<5.1.3",
				Criticality: "Moderately critical 11\u2009∕\u200925 AC:Complex/A:User/CI:Some/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Cross-site request forgery",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-063",
			},
		},
	},
	"wisski": {
		Slug: "wisski",
		ProjectName: "WissKI 8.x-4.2",
		ProjectURL: "https://www.drupal.org/project/wisski/releases/8.x-4.2",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13239",
				Versions: "<4.2.0",
				Criticality: "Critical 17\u2009∕\u200925 AC:None/A:None/CI:Some/II:Some/E:Theoretical/TD:Default",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-059",
			},
		},
	},
	"ai": {
		Slug: "ai",
		ProjectName: "AI 1.4.3",
		ProjectURL: "https://www.drupal.org/project/ai/releases/1.4.3",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13235",
				Versions: "<1.2.17 || >=1.3.0 <1.3.8 || >=1.4.0 <1.4.3",
				Criticality: "Moderately critical 10\u2009∕\u200925 AC:Complex/A:Admin/CI:Some/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-055",
			},
			{
				CVE: "CVE-2026-13234",
				Versions: "<1.2.17 || >=1.3.0 <1.3.8 || >=1.4.0 <1.4.3",
				Criticality: "Moderately critical 14\u2009∕\u200925 AC:Complex/A:None/CI:Some/II:Some/E:Theoretical/TD:Default",
				Vulnerability: "Information Disclosure / Cross-site Scripting",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-054",
			},
		},
	},
	"ai_provider_openai": {
		Slug: "ai_provider_openai",
		ProjectName: "OpenAI Provider 1.2.2",
		ProjectURL: "https://www.drupal.org/project/ai_provider_openai/releases/1.2.2",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13233",
				Versions: "<1.1.1 || >=1.2.0 <1.2.2",
				Criticality: "Moderately critical 10\u2009∕\u200925 AC:Complex/A:Admin/CI:Some/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Server-side Request Forgery",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-053",
			},
		},
	},
	"core": {
		Slug: "core",
		ProjectName: "Drupal 10.5.12",
		ProjectURL: "https://www.drupal.org/project/drupal/releases/10.5.12",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-55808",
				Versions: "<10.5.12 || >=10.6.0 <10.6.11 || >=11.2.0 <11.2.14 || >=11.3.0 <11.3.12 || 11.0.* || 11.1.*",
				Criticality: "Moderately critical 11\u2009∕\u200925 AC:Complex/A:User/CI:Some/II:Some/E:Theoretical/TD:Uncommon",
				Vulnerability: "Improper validation",
				IssueURL: "https://www.drupal.org/sa-core-2026-009",
			},
			{
				CVE: "CVE-2026-55807",
				Versions: "<10.5.12 || >=10.6.0 <10.6.11 || >=11.2.0 <11.2.14 || >=11.3.0 <11.3.12 || 11.0.* || 11.1.*",
				Criticality: "Moderately critical 10\u2009∕\u200925 AC:Basic/A:User/CI:Some/II:None/E:Theoretical/TD:Default",
				Vulnerability: "Server-side request forgery",
				IssueURL: "https://www.drupal.org/sa-core-2026-008",
			},
			{
				CVE: "CVE-2026-55806",
				Versions: "<10.5.12 || >=10.6.0 <10.6.11 || >=11.2.0 <11.2.14 || >=11.3.0 <11.3.12 || 11.0.* || 11.1.*",
				Criticality: "Less critical 9\u2009∕\u200925 AC:Basic/A:None/CI:None/II:None/E:Theoretical/TD:Default",
				Vulnerability: "Cache poisoning and open redirect",
				IssueURL: "https://www.drupal.org/sa-core-2026-007",
			},
			{
				CVE: "CVE-2026-55804",
				Versions: "<10.5.12 || >=10.6.0 <10.6.11 || >=11.2.0 <11.2.14 || >=11.3.0 <11.3.12 || 11.0.* || 11.1.*",
				Criticality: "Moderately critical 14\u2009∕\u200925 AC:Complex/A:Admin/CI:All/II:All/E:Theoretical/TD:Uncommon",
				Vulnerability: "Gadget chain",
				IssueURL: "https://www.drupal.org/sa-core-2026-006",
			},
			{
				CVE: "CVE-2026-55803",
				Versions: "<10.5.12 || >=10.6.0 <10.6.11 || >=11.2.0 <11.2.14 || >=11.3.0 <11.3.12 || 11.0.* || 11.1.*",
				Criticality: "Critical 18\u2009∕\u200925 AC:None/A:User/CI:All/II:All/E:Theoretical/TD:Uncommon",
				Vulnerability: "PHP object injection",
				IssueURL: "https://www.drupal.org/sa-core-2026-005",
			},
		},
	},
}
