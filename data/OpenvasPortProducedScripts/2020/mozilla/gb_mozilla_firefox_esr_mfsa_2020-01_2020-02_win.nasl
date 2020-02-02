# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815883");
  script_version("2020-01-16T07:57:40+0000");
  script_cve_id("CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17021",
                "CVE-2019-17022", "CVE-2019-17024");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:57:40 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-08 13:10:43 +0530 (Wed, 08 Jan 2020)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2020-01_2020-02)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A memory corruption error in parent process during new content process
    initialization on Windows.

  - Bypass of namespace CSS sanitization during pasting.

  - A type Confusion error in XPCVariant.cpp.

  - CSS sanitization does not escape HTML tags.

  - Heap address disclosure in parent process during content process initialization.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to run arbitrary code, disclose sensitive information, conduct xss attacks
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 68.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 68.4
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-02/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"68.4"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"68.4", install_path:ffPath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
