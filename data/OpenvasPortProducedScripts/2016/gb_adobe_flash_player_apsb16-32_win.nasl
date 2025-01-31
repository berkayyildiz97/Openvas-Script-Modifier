##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Security Updates( apsb16-32 )-Windows
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809441");
  script_version("2019-10-23T10:55:06+0000");
  script_cve_id("CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982",
                "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986",
                "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992");
  script_bugtraq_id(93490, 93497, 93492);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-23 10:55:06 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-10-12 19:02:24 +0530 (Wed, 12 Oct 2016)");
  script_name("Adobe Flash Player Security Updates( apsb16-32 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - A type confusion vulnerability.

  - The use-after-free vulnerabilities.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers lead to code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.382 and 22.x before 23.0.0.185 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.382, or 23.0.0.185, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-32.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"22", test_version2:"23.0.0.184"))
{
  fix = "23.0.0.185";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.382"))
{
  fix = "18.0.0.382";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:fix);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

