###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_arb_code_exec_vuln01_feb14_mac.nasl 34994 2014-02-05 15:20:29Z Feb$
#
# Adobe Flash Player Arbitrary Code Execution Vulnerability - 01 Feb14 (Mac OX S)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804086");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2014-0497");
  script_bugtraq_id(65327);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2014-02-05 15:20:29 +0530 (Wed, 05 Feb 2014)");
  script_name("Adobe Flash Player Arbitrary Code Execution Vulnerability - 01 Feb14 (Mac OX S)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to arbitrary
code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an integer underflow condition that is triggered as unspecified
user-supplied input is not properly validated.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, execute arbitrary code and
cause buffer overflow.");
  script_tag(name:"affected", value:"Adobe Flash Player versions before 11.7.700.261 and 11.8.x through 12.0.x
before 12.0.0.44 on Mac OS X");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.261 or 12.0.0.44 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56737");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-04.html");
  script_xref(name:"URL", value:"http://krebsonsecurity.com/2014/02/adobe-pushes-fix-for-flash-zero-day-attack");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.7.700.261") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"12.0.0.43"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
