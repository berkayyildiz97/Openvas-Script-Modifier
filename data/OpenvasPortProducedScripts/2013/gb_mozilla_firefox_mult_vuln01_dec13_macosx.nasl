###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_dec13_macosx.nasl 33846 2013-12-23 16:51:47Z dec$
#
# Mozilla Firefox Multiple Vulnerabilities-01 Dec13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804040");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5611", "CVE-2013-5612",
                "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616",
                "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672",
                "CVE-2013-6673");
  script_bugtraq_id(64204, 64206, 64214, 64205, 64203, 64207, 64216, 64209, 64211, 64215, 64212, 64210, 64213);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-12-23 16:51:47 +0530 (Mon, 23 Dec 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Dec13 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 26.0 or later.");
  script_tag(name:"insight", value:"For more details about the vulnerabilities, refer the reference section.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 26.0 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, disclose potentially sensitive
information, and compromise a user's system.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56002");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"26.0"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
