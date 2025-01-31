###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox CSP Information Disclosure Vulnerability Dec14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805218");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2014-1591");
  script_bugtraq_id(71399);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2014-12-16 09:53:28 +0530 (Tue, 16 Dec 2014)");
  script_name("Mozilla Firefox CSP Information Disclosure Vulnerability Dec14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to an error when handling
  Content Security Policy (CSP) violation reports triggered by a redirect.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to usernames or single-sign-on tokens.");

  script_tag(name:"affected", value:"Mozilla Firefox version 33.0 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 34.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60605");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-86");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_equal(version:ffVer, test_version:"33.0"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
