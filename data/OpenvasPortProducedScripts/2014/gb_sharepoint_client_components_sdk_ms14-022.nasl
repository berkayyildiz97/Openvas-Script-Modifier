###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Client Components SDK Multiple Vulnerabilities (2952166)
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804584");
  script_version("2020-01-07T08:11:35+0000");
  script_cve_id("CVE-2014-0251", "CVE-2014-1754");
  script_bugtraq_id(67283, 67288);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-07 08:11:35 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-05-14 15:58:55 +0530 (Wed, 14 May 2014)");
  script_name("Microsoft SharePoint Client Components SDK Multiple Vulnerabilities (2952166)");

  script_tag(name:"summary", value:"This host is missing an critical security update according to Microsoft
  Bulletin MS14-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is due to multiple unspecified components when handling page content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 Client Components SDK 32/64 bit");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-022");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

shareVer = get_app_version(cpe:CPE);
if(!shareVer){
  exit(0);
}

## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\15\ISAPI";

    dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.sharepoint.client.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4609.999"))
      {
        if(!port = get_app_port(cpe: CPE)) port = 0;
        security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
        exit(0);
      }
    }
  }
}
