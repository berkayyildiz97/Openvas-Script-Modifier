###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server WAS Remote Code Execution Vulnerability (3115466)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809044");
  script_version("2019-12-20T10:24:46+0000");
  script_cve_id("CVE-2016-3357");
  script_bugtraq_id(92786);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 10:24:16 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server WAS Remote Code Execution Vulnerability (3115466)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Office software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010 Service Pack 2 Word Automation Services,

  - Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115443");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115466");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2010
if(shareVer =~ "^14\..*")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7172.4999"))
    {
      report = 'File checked:     ' +  path + "\14.0\WebServices\WordServer\Core\sword.dll" + '\n' +
               'File version:     ' +  dllVer2  + '\n' +
               'Vulnerable range: ' +  "14.0 - 14.0.7172.4999" + '\n' ;
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\..*")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\15.0\WebServices\ConversionServices\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4859.999"))
    {
      report = 'File checked:     ' +  path + "\15.0\WebServices\ConversionServices\sword.dll"+ '\n' +
               'File version:     ' +  dllVer2  + '\n' +
               'Vulnerable range: ' +  "15.0 - 15.0.4859.999" + '\n' ;
      if(!port = get_app_port(cpe: CPE)) port = 0;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
