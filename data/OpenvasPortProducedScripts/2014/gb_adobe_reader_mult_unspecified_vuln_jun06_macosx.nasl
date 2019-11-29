###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln_jun06_macosx.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Adobe Reader Multiple Unspecified Vulnerabilities Jun06 (Mac OS X)
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804391");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2006-3093");
  script_bugtraq_id(18445);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-11 14:22:24 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities Jun06 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to have unspecified impact.");
  script_tag(name:"affected", value:"Adobe Reader before version 7.0.8 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 7.0.8 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/20576");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016314");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31829");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/327817.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/reader");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer)
{
  if(version_is_less(version:readerVer, test_version:"7.0.8"))
  {
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
    exit(0);
  }
}
