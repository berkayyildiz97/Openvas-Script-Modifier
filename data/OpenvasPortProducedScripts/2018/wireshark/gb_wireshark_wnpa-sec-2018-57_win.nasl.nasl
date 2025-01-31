###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark 'ZigBee ZCL' Dissector Denial of Service Vulnerability (wnpa-sec-2018-57)-Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814506");
  script_version("2019-07-05T09:12:25+0000");
  script_cve_id("CVE-2018-19628");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-11-29 11:27:40 +0530 (Thu, 29 Nov 2018)");
  script_name("Wireshark 'ZigBee ZCL' Dissector Denial of Service Vulnerability (wnpa-sec-2018-57)-Windows");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in 'ZigBee ZCL'
  dissector could crash.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash by injecting a malformed packet onto the wire or by convincing someone
  to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark versions 2.6.0 to 2.6.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.6.5 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-57");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
wirversion = infos['version'];
path = infos['location'];

if(version_in_range(version:wirversion, test_version:"2.6.0", test_version2:"2.6.4"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.6.5", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
