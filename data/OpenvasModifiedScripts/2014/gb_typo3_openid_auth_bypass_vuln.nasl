###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_openid_auth_bypass_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# TYPO3 OpenID Authentication Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803992");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2010-0286");
  script_bugtraq_id(38438);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-30 17:01:48 +0530 (Mon, 30 Dec 2013)");
  script_name("TYPO3 OpenID Authentication Bypass Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exist in the built-in OpenID extension, which fails to verify user
identities properly");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.3.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to authentication bypass
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 versions 4.3.0");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55609");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38206");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-001/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  if(version_is_equal(version:typoVer, test_version:"4.3.0"))
  {
    report = report_fixed_ver(installed_version:typoVer, vulnerable_range:"Equal to 4.3.0");
    security_message(port: typoPort, data: report);
    exit(0);
  }
}
