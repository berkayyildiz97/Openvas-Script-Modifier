###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sepsb_rar_file_parser_dos_vuln_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Symantec Endpoint Protection Small Business Edition RAR File Parser DoS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810937");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-25 14:16:42 +0530 (Tue, 25 Apr 2017)");
  script_name("Symantec Endpoint Protection Small Business Edition RAR File Parser DoS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection Small Business Edition and is prone to denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to mishandling of
  RAR file by RAR file parser component in the AntiVirus Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (out-of-bounds read) via a crafted RAR
  file that is mishandled during decompression.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection Small Business
  Edition 12.1.");

  script_tag(name:"solution", value:"Upgrade to SEP SBE (Hosted) or Symantec Endpoint
  Protection Enterprise Edition (EE) 12.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40405");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.TECH235368.html");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160919_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/SEP/SmallBusiness");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:sepVer, test_version:"12.1"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"Upgrade to SEP SBE (Hosted) or SEP (EE) 12.1");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
