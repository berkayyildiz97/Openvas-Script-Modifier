###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities-01 June15 (Linux)
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805586");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-3108", "CVE-2015-3107", "CVE-2015-3106", "CVE-2015-3105",
                "CVE-2015-3104", "CVE-2015-3103", "CVE-2015-3102", "CVE-2015-3101",
                "CVE-2015-3100", "CVE-2015-3099", "CVE-2015-3098", "CVE-2015-3096");
  script_bugtraq_id(75084, 75087, 75086, 75081, 75080, 75089, 75085, 75088);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-06-15 12:16:31 +0530 (Mon, 15 Jun 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 June15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error which does not properly restrict discovery of memory addresseses.

  - Multiple use-after-free errors.

  - A memory corruption error.

  - An integer overflow error.

  - Multiple unspecified errors bypassing same origin policy.

  - An error due to permission issue in the flash broker for internet explorer.

  - A stack overflow error.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, execute arbitrary code,
  cause a denial of service, bypass the same origin policy and bypass certain
  protection mechanism.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  11.2.202.466 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.466 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"11.2.202.466"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "11.2.202.466" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
