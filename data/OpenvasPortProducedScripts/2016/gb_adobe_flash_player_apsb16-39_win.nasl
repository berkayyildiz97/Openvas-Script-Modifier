##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Security Updates-ms16-154 (3209498)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810311");
  script_version("2019-10-23T10:55:06+0000");
  script_cve_id("CVE-2016-7867", "CVE-2016-7868", "CVE-2016-7869", "CVE-2016-7870",
                "CVE-2016-7871", "CVE-2016-7872", "CVE-2016-7873", "CVE-2016-7874",
                "CVE-2016-7875", "CVE-2016-7876", "CVE-2016-7877", "CVE-2016-7878",
                "CVE-2016-7879", "CVE-2016-7880", "CVE-2016-7881", "CVE-2016-7890",
                "CVE-2016-7892");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-23 10:55:06 +0000 (Wed, 23 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-12-14 09:54:24 +0530 (Wed, 14 Dec 2016)");
  script_name("Adobe Flash Player Security Updates-ms16-154 (3209498)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - An use-after-free vulnerabilities.

  - The buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to take control of the
  affected system, and lead to code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version
  23.x before 24.0.0.186 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  24.0.0.186 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms16-154");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-39.html");

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

if(version_in_range(version:playerVer, test_version:"23.0", test_version2:"24.0.0.185"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"24.0.0.186");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

