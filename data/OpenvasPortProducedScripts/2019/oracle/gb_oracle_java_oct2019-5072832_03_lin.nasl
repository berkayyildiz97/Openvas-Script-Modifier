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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815643");
  script_version("2019-11-27T15:23:21+0000");
  script_cve_id("CVE-2019-2987", "CVE-2019-2977");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-10-16 10:32:00 +0530 (Wed, 16 Oct 2019)");
  script_name("Oracle Java SE Security Updates (oct2019-5072832) 03 - Linux");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to errors in
  'Hotspot' and '2D' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to have an impact on confidentiality and availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 11.0.4 and earlier, 13 on Linux");

  script_tag(name:"solution", value:"Apply the patch");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:oracle:jdk";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
}

jreVer = infos['version'];
path = infos['location'];

if(!jreVer){
  exit(0);
}

if(version_in_range(version:jreVer, test_version:"11.0", test_version2:"11.0.4")||
   version_is_equal(version:jreVer, test_version:"13.0"))
{
  report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
