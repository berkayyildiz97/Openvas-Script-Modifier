###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_sec_bypass_vuln_june15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Air Security Bypass Vulnerability - June15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805590");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3097");
  script_bugtraq_id(75090);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-15 13:30:22 +0530 (Mon, 15 Jun 2015)");
  script_name("Adobe Air Security Bypass Vulnerability - June15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Air and
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to improper selection
  of a random memory address for the Flash heap.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and execute arbitrary code on
  affected system.");

  script_tag(name:"affected", value:"Adobe Air versions before 18.0.0.180 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Air version 18.0.0.180
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win7x64:2) <= 0){
  exit(0);
}

if(!airVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:airVer, test_version:"18.0.0.180"))
{
  report = 'Installed version: ' + airVer + '\n' +
           'Fixed version:     ' + "18.0.0.180" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
