###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Denial of Service Vulnerabilities - February 11(Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801748");
  script_version("2019-07-17T08:15:16+0000");
  script_tag(name:"last_modification", value:"2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2011-0981", "CVE-2011-0982", "CVE-2011-0983",
                "CVE-2011-0984", "CVE-2011-0985");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities - February 11(Linux)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_08.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial-of-service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 9.0.597.94");
  script_tag(name:"insight", value:"The flaws are due to

  - Not properly performing event handling for animations

  - Use-after-free error in SVG font faces

  - Not properly handling anonymous blocks

  - Out-of-bounds read in plug-in handling

  - Not properly performing process termination upon memory exhaustion");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 9.0.597.94 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"9.0.597.94")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"9.0.597.94");
  security_message(port: 0, data: report);
}
