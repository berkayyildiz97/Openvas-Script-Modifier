###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Security Bypass Vulnerability - Aug15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806006");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-4495");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-08-10 15:41:41 +0530 (Mon, 10 Aug 2015)");
  script_name("Mozilla Firefox ESR Security Bypass Vulnerability - Aug15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  interaction of the mechanism that enforces JavaScript context separation
  and Firefox PDF Viewer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read and steal sensitive local files on the victim's computer.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 38.x
  before 38.1.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-78/");
  script_xref(name:"URL", value:"https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_in_range(version:ffVer, test_version:"38.0", test_version2:"38.1.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.1.1" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
