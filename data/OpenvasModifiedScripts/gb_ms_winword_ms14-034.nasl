###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Remote Code Execution Vulnerability (2969261)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804457");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2014-2778");
  script_bugtraq_id(67896);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2014-06-11 08:36:13 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2969261)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS14-034.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error when processing embedded fonts,
  which can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system.");

  script_tag(name:"affected", value:"Microsoft Word 2007 Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58551");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2880515");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-034");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2003/2007/2010
if(winwordVer && winwordVer =~ "^12\.")
{
  if(version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6700.4999"))
  {
    report = report_fixed_ver(installed_version:winwordVer, fixed_version:"12.0.6700.5000");
    security_message(data:report);
    exit(0);
  }
}
