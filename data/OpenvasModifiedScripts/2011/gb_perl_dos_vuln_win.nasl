###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_dos_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Perl Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801790");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-0761");
  script_bugtraq_id(47766);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Perl Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67355");
  script_xref(name:"URL", value:"http://www.toucan-system.com/advisories/tssa-2011-03.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/517916/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause an affected
  application to crash, denying service to legitimate users.");
  script_tag(name:"affected", value:"Perl versions 5.10 and 5.10.1 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'getpeername', 'readdir', 'closedir',
  'getsockname', 'rewinddir', 'tell', or 'telldir' function calls. When given
  a wrong number of arguments, those functions will attempt to perform a
  comparison between an unallocated memory zone and a given register, resulting
  in a segmentation fault.");
  script_tag(name:"solution", value:"Upgrade to Perl version 5.12 or later.");
  script_tag(name:"summary", value:"The host is installed with Perl and is prone to denial of service
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.perl.org/get.html");
  exit(0);
}


include("version_func.inc");

apVer = get_kb_item("ActivePerl/Ver");
if(apVer)
{
  if(version_in_range(version:apVer, test_version:"5.10", test_version2:"5.10.1"))
  {
    report = report_fixed_ver(installed_version:apVer, vulnerable_range:"5.10 - 5.10.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

spVer = get_kb_item("Strawberry/Perl/Ver");
if(spVer)
{
  if(version_in_range(version:spVer, test_version:"5.10", test_version2:"5.10.1")){
    report = report_fixed_ver(installed_version:spVer, vulnerable_range:"5.10 - 5.10.1");
    security_message(port: 0, data: report);
  }
}
