##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Security Updates(apsb17-15)-Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811101");
  script_version("2019-10-23T10:55:06+0000");
  script_cve_id("CVE-2017-3068", "CVE-2017-3069", "CVE-2017-3070", "CVE-2017-3071",
                "CVE-2017-3072", "CVE-2017-3073", "CVE-2017-3074");
  script_bugtraq_id(98349, 98347);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-23 10:55:06 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 07:59:40 +0530 (Wed, 10 May 2017)");
  script_name("Adobe Flash Player Security Updates( apsb17-15 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A use-after-free vulnerability and

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute the code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  25.0.0.171 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  25.0.0.171 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"25.0.0.171"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"25.0.0.171");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
