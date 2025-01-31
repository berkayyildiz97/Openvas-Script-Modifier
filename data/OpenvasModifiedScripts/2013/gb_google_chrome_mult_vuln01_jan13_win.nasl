###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities-01 Jan2013 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803157");
  script_version("2019-07-17T08:15:16+0000");
  script_cve_id("CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148",
                "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152",
                "CVE-2012-5153", "CVE-2012-5154", "CVE-2012-5156", "CVE-2012-5157",
                "CVE-2013-0828", "CVE-2013-0829", "CVE-2013-0830", "CVE-2013-0831",
                "CVE-2013-0832", "CVE-2013-0833", "CVE-2013-0834", "CVE-2013-0835",
                "CVE-2013-0836", "CVE-2013-0837");
  script_bugtraq_id(57251);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-01-17 14:39:55 +0530 (Thu, 17 Jan 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Jan2013 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51825/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027977");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/01/stable-channel-update.html");

  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 24.0.1312.52 on Windows");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 24.0.1312.52 or later.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"24.0.1312.52")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"24.0.1312.52");
  security_message(port: 0, data: report);
}
