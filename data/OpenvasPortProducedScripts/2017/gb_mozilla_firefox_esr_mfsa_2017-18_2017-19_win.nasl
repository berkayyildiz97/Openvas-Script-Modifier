###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Security Updates(mfsa_2017-18_2017-19)-Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811573");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2017-7798", "CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7809",
                "CVE-2017-7784", "CVE-2017-7802", "CVE-2017-7785", "CVE-2017-7786",
                "CVE-2017-7753", "CVE-2017-7787", "CVE-2017-7807", "CVE-2017-7792",
                "CVE-2017-7804", "CVE-2017-7791", "CVE-2017-7782", "CVE-2017-7803",
                "CVE-2017-7779");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-08-10 11:41:29 +0530 (Thu, 10 Aug 2017)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2017-18_2017-19)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - XUL injection in the style editor in devtools.

  - Use-after-free in WebSockets during disconnection.

  - Use-after-free with marquee during window resizing.

  - Use-after-free while deleting attached editor DOM node.

  - Use-after-free with image observers.

  - Use-after-free resizing image elements.

  - Buffer overflow manipulating ARIA attributes in DOM.

  - Buffer overflow while painting non-displayable SVG.

  - Out-of-bounds read with cached style data and pseudo-elements.

  - Same-origin policy bypass with iframes through page reloads.

  - Domain hijacking through AppCache fallback.

  - Buffer overflow viewing certificates with an extremely long OID.

  - Memory protection bypass through WindowsDllDetourPatcher.

  - Spoofing following page navigation with data: protocol and modal alerts.

  - WindowsDllDetourPatcher allocates memory without DEP protections.

  - CSP containing sandbox is improperly applied.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code,
  conduct spoofing attack, cause information disclosure, bypass existing
  memory protections and cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  52.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 52.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-19/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"52.3"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.3");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
