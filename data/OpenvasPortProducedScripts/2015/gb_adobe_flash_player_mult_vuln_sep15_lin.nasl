###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities Sep15 (Linux)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805742");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-5567", "CVE-2015-5568", "CVE-2015-5570", "CVE-2015-5571",
                "CVE-2015-5572", "CVE-2015-5573", "CVE-2015-5574", "CVE-2015-5575",
                "CVE-2015-5576", "CVE-2015-5577", "CVE-2015-5578", "CVE-2015-5579",
                "CVE-2015-5580", "CVE-2015-5581", "CVE-2015-5582", "CVE-2015-5584",
                "CVE-2015-5587", "CVE-2015-5588", "CVE-2015-6676", "CVE-2015-6677",
                "CVE-2015-6678", "CVE-2015-6679", "CVE-2015-6682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-09-24 13:05:29 +0530 (Thu, 24 Sep 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities Sep15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption errors.

  - Multiple unspecified errors.

  - Multiple use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, conduct denial
  of service attack and potentially execute arbitrary code in the context of the
  affected user.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  11.2.202.521 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  11.2.202.521 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");
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

## Fix will be updated once the solution details are available
if(version_is_less(version:playerVer, test_version:"11.2.202.521"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "11.2.202.521" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
