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


CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815715");
  script_version("2020-01-16T07:57:40+0000");
  script_cve_id("CVE-2018-6156", "CVE-2019-15903", "CVE-2019-11757", "CVE-2019-11759",
                "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763",
                "CVE-2019-11765", "CVE-2019-17000", "CVE-2019-17001", "CVE-2019-17002",
                "CVE-2019-11764");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:57:40 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-10-23 13:07:48 +0530 (Wed, 23 Oct 2019)");
  script_name("Mozilla Firefox Security Updates( mfsa_2019-33_2019-34 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - A heap buffer overflow issue in FEC processing in WebRTC.

  - A heap overflow issue in expat library in XML_GetCurrentLineNumber.

  - A use-after-free issue when creating index updates in IndexedDB.

  - A stack buffer overflow issue in HKDF output and WebRTC networking.

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to crash the application,
  bypass security restrictions and conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 70 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 70
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-34/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"70"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"70", install_path:ffPath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
