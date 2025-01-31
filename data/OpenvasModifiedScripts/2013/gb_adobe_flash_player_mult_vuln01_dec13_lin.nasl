###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities-01 Dec13 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804169");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2013-5331", "CVE-2013-5332");
  script_bugtraq_id(64199, 64201);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-12-18 16:01:12 +0530 (Wed, 18 Dec 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Dec13 (Linux)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.2.202.332 or later.");
  script_tag(name:"insight", value:"Flaws are due to multiple unspecified errors.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 11.2.202.332 on Linux.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption(denial of service) and compromise a user's system.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55948");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb13-28.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.332"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.332");
  security_message(port: 0, data: report);
  exit(0);
}
