###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_integer_overflow_vuln_nov13_macosx.nasl 31965 2013-11-25 21:28:51Z nov$
#
# Mozilla Firefox Integer Overflow Vulnerability-01 Nov13 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804152");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2013-5607");
  script_bugtraq_id(63802);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-11-25 21:28:51 +0530 (Mon, 25 Nov 2013)");
  script_name("Mozilla Firefox Integer Overflow Vulnerability-01 Nov13 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to integer overflow
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 25.0.1 or later.");
  script_tag(name:"insight", value:"The flaw is due to integer overflow in the 'PL_ArenaAllocate' function
in Mozilla Netscape Portable Runtime (NSPR).");
  script_tag(name:"affected", value:"Mozilla Firefox before version 25.0.1 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55732");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-103.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/current/0105.html");
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

if(version_is_less(version:ffVer, test_version:"25.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"25.0.1");
  security_message(port: 0, data: report);
  exit(0);
}

