###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities -02 Feb13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803407");
  script_version("2019-07-17T11:14:11+0000");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-02-14 12:22:01 +0530 (Thu, 14 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642",
                "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649",
                "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368",
                "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373",
                "CVE-2013-1374");
  script_bugtraq_id(57929, 57926, 57925, 57923, 57933, 57916, 57927, 57930, 57920,
                    57924, 57922, 57918, 57919, 57912, 57917);
  script_name("Adobe Flash Player Multiple Vulnerabilities -02 Feb13 (Windows)");
  script_xref(name:"URL", value:"https://lwn.net/Articles/537746");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52166");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer overflow,
  remote code execution and corrupt system memory.");
  script_tag(name:"affected", value:"Adobe Flash Player prior to 10.3.183.63 and 11.x prior to 11.6.602.168
  on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to

  - Dereference already freed memory

  - Use-after-free errors

  - Integer overflow and some unspecified error.");
  script_tag(name:"solution", value:"Update to version 11.6.602.168 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"10.3.183.63" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.6.602.167" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.6.602.168", install_path:path );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
