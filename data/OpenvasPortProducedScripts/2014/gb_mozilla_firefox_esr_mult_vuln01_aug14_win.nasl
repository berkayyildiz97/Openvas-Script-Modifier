###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mult_vuln01_aug14_win.nasl 39607 2014-08-07 09:58:30Z Aug$
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 August14 (Windows)
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804732");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2014-1547", "CVE-2014-1555", "CVE-2014-1557",
                "CVE-2014-1551", "CVE-2014-1544", "CVE-2014-1556");
  script_bugtraq_id(68811, 68814, 68824, 68817, 68816, 68822);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2014-08-07 10:02:33 +0530 (Thu, 07 Aug 2014)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 August14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free error related to ordering of control messages for Web Audio.

  - A use-after-free error in DirectWrite when rendering MathML.

  - A use-after-free error when handling the FireOnStateChange event.

  - An unspecified error when using the Cesium JavaScript library to generate
  WebGL content.
and Some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version 24.x before 24.7 on Windows");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 24.7 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59803");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-56.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ffVer =~ "^24\." && version_in_range(version:ffVer,
                       test_version:"24.0", test_version2:"24.6"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
