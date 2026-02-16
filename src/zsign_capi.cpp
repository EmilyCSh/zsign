#include "common.h"
#include "archive.h"
#include "bundle.h"
#include "macho.h"
#include "openssl.h"
#include <string>

extern "C" {

int zsign_sign_folder_to_ipa(const char* app_folder, const char* prov_path, const char* key_path)
{
    try {
        if (!app_folder) {
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
