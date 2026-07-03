package pkg

var Projects = map[string]Output{
	"admin_feedback": {
		Slug: "admin_feedback",
		ProjectName: "admin_feedback 8.x-2.8",
		ProjectURL: "https://www.drupal.org/project/admin_feedback/releases/8.x-2.8",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13232",
				Versions: "<2.8.0",
				Criticality: "HIGH",
				Vulnerability: "Access bypass / Insecure Direct Object Reference (IDOR)",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-052",
			},
			{
				CVE: "CVE-2026-13231",
				Versions: "<2.8.0",
				Criticality: "HIGH",
				Vulnerability: "Cross-site scripting",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-051",
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
				Criticality: "HIGH",
				Vulnerability: "Improper validation",
				IssueURL: "https://www.drupal.org/sa-core-2026-009",
			},
		},
	},
	"colorbox": {
		Slug: "colorbox",
		ProjectName: "Colorbox 2.2.1",
		ProjectURL: "https://www.drupal.org/project/colorbox/releases/2.2.1",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-58591",
				Versions: "< 2.1.5 || 2.2.0",
				Criticality: "HIGH",
				Vulnerability: "Cross-site scripting",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-069",
			},
		},
	},
	"canvas": {
		Slug: "canvas",
		ProjectName: "1.7.1",
		ProjectURL: "https://www.drupal.org/project/canvas/releases/1.7.1",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-58588",
				Versions: "<1.4.2 || >=1.5.0 <1.5.2 || >=1.6.0 <1.6.1 || >=1.7.0 <1.7.1",
				Criticality: "HIGH",
				Vulnerability: "Improper validation",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-066",
			},
			{
				CVE: "CVE-2026-58587",
				Versions: "<1.4.2 || >=1.5.0 <1.5.2 || >=1.6.0 <1.6.1 || >=1.7.0 <1.7.1",
				Criticality: "HIGH",
				Vulnerability: "Improper validation",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-065",
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
				Criticality: "HIGH",
				Vulnerability: "Cross-site request forgery",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-063",
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
				Criticality: "HIGH",
				Vulnerability: "Access Bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-058",
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
				Criticality: "HIGH",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-055",
			},
			{
				CVE: "CVE-2026-13234",
				Versions: "<1.2.17 || >=1.3.0 <1.3.8 || >=1.4.0 <1.4.3",
				Criticality: "HIGH",
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
				Criticality: "HIGH",
				Vulnerability: "Server-side Request Forgery",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-053",
			},
		},
	},
	"flowdrop": {
		Slug: "flowdrop",
		ProjectName: "FlowDrop 1.6.0",
		ProjectURL: "https://www.drupal.org/project/flowdrop/releases/1.6.0",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-58590",
				Versions: "<1.6.0",
				Criticality: "HIGH",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-068",
			},
			{
				CVE: "CVE-2026-58589",
				Versions: "<1.6.0",
				Criticality: "HIGH",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-067",
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
				Criticality: "CRITICAL",
				Vulnerability: "PHP object injection",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-064",
			},
		},
	},
	"geolocation": {
		Slug: "geolocation",
		ProjectName: "Geolocation Field 8.x-3.15",
		ProjectURL: "https://www.drupal.org/project/geolocation/releases/8.x-3.15",
		Advisories: []AdvisoryItem{
			{
				CVE: "CVE-2026-13242",
				Versions: "<3.15.0",
				Criticality: "CRITICAL",
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
				Criticality: "HIGH",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-061",
			},
			{
				CVE: "CVE-2026-13240",
				Versions: "<1.21.0",
				Criticality: "MEDIUM",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-060",
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
				Criticality: "CRITICAL",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-059",
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
				Criticality: "HIGH",
				Vulnerability: "Information disclosure, Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-057",
			},
			{
				CVE: "CVE-2026-13236",
				Versions: "<1.1.4 || >=1.2.0 <1.2.5 || >=1.3.0 <1.3.1",
				Criticality: "MEDIUM",
				Vulnerability: "Access bypass",
				IssueURL: "https://www.drupal.org/sa-contrib-2026-056",
			},
		},
	},
}
