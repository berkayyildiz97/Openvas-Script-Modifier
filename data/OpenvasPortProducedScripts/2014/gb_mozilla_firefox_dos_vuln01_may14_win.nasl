###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_dos_vuln01_may14_win.nasl 37404 2014-05-06 16:23:01Z may$
#
# Mozilla Firefox Denial of Service Vulnerability-01 May14 (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804570");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2014-1518");
  script_bugtraq_id(67133);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2014-05-06 16:23:01 +0530 (Tue, 06 May 2014)");
  script_name("Mozilla Firefox Denial of Service Vulnerability-01 May14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws is due to an error exists when working with canvas within the
'sse2_composite_src_x888_8888()' function in the Cairo graphics library.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
or cause a denial of service.");
  script_tag(name:"affected", value:"Mozilla Firefox version 28.0 on Windows");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 29.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58234");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ffVer, test_version:"28.0"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
