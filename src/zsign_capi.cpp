#include "common.h"
#include "archive.h"
#include "bundle.h"
#include "macho.h"
#include "openssl.h"
#include <string>

extern "C" {

int zsign_sign_folder_to_ipa(const char* app_folder, const char* output_ipa, const char* prov_path, const char* key_path, char** out_bundle_id, char** out_bundle_ver)
{
    try {
        if (!app_folder || !output_ipa) {
            return -1;
        }

        ZSignAsset zsa;
        std::string cert="";
        std::string pkey = key_path ? key_path : "";
        std::string prov = prov_path ? prov_path : "";
        std::string ent="";
        std::string pwd="";

        if (!zsa.Init(cert, pkey, prov, ent, pwd, false, false, false)) {
            return -2;
        }

        ZBundle bundle;
        std::string strFolder = app_folder;
        std::vector<std::string> empty;

        bool ok = bundle.SignFolder(&zsa, strFolder, "", "", "", empty, true, false, false);
        if (!ok) {
            return -3;
        }

        std::string infoPath = bundle.m_strAppFolder + "/Info.plist";

        jvalue jvInfo;
        if (!jvInfo.read_plist_from_file(infoPath.c_str())) {
            return -4;
        }

        std::string bundle_id = jvInfo["CFBundleIdentifier"].as_cstr();
        std::string bundle_ver = jvInfo["CFBundleVersion"].as_cstr();

        size_t pos = bundle.m_strAppFolder.rfind("Payload");
        if (std::string::npos == pos) {
            if (!Zip::Archive(bundle.m_strAppFolder.c_str(), output_ipa, 9)) {
                return -5;
            }
        } else {
            std::string baseFolder = bundle.m_strAppFolder.substr(0, pos - 1);

            if (!Zip::Archive(baseFolder.c_str(), output_ipa, 9)) {
                return -5;
            }
        }

        if (bundle_id.empty() || bundle_ver.empty()) {
            return -6;
        }

        if (out_bundle_id) {
            *out_bundle_id = strdup(bundle_id.c_str());
        }

        if (out_bundle_ver) {
            *out_bundle_ver = strdup(bundle_ver.c_str());
        }

        return 0;
    } catch(const std::runtime_error& re) {
        std::cerr << "Runtime error: " << re.what() << std::endl;
        return -7;
    } catch(const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return -8;
    } catch(...) {
        std::cerr << "Unknown exception occurred." << std::endl;
        return -9;
    }
}

} // extern "C"
