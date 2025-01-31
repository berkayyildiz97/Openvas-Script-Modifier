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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815828");
  script_version("2019-11-06T11:51:43+0000");
  script_cve_id("CVE-2019-8784", "CVE-2019-8801", "CVE-2019-8813", "CVE-2019-8782",
                "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812",
                "CVE-2019-8814", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820",
                "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823", "CVE-2019-8815");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-11-06 11:51:43 +0000 (Wed, 06 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-05 15:24:05 +0530 (Tue, 05 Nov 2019)");
  script_name("Apple iTunes Security Updates(HT210726)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A dynamic library loading issue existed in iTunes setup.

  - A logic issue related to improper state management.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to conduct cross site scripting attacks and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.10.2 on Windows");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.10.2 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-in/HT210726");
  script_xref(name:"URL", value:"https://www.apple.com/in/itunes/download/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
ituneVer = infos['version'];
itunePath = infos['location'];

if(version_is_less(version:ituneVer, test_version:"12.10.2"))
{
  report = report_fixed_ver(installed_version: ituneVer, fixed_version:"12.10.2", install_path: itunePath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
