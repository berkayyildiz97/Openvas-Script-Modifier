# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815239");
  script_version("2019-08-08T06:47:52+0000");
  script_cve_id("CVE-2019-9811", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713",
                "CVE-2019-11729", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719",
                "CVE-2019-11730", "CVE-2019-11709");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-08 06:47:52 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 09:43:26 +0530 (Thu, 11 Jul 2019)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2019-21_2019-22)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Sandbox escape via installation of malicious language pack.

  - Script injection within domain through inner window reuse.

  - POST requests made by NPAPI plugins can lead to Cross-Site Request Forgery
    (CSRF) attacks.

  - A use-after-free issue in HTTP/2 cached stream.

  - Empty or malformed p256-ECDH public keys may trigger a segmentation fault.

  - Improper esacping of Caret character in origins.

  - An out-of-bounds read issue when importing curve25519 private key.

  - Same-origin policy treats all files in a directory as having the same-origin.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the browser, bypass certain security
  restrictions to perform unauthorized actions, or to steal cookie-based
  authentication credentials.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 60.8 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 60.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-22/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/organizations/all/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"60.8"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"60.8", install_path:ffPath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
