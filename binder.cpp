#include <iostream>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>  // For STL container support
#include <pybind11/complex.h>
#include <pybind11/functional.h> 
#include <pybind11/chrono.h>
#include "ciphers/pasta_3/plain/pasta_3_plain.h"
#include "ciphers/pasta_3/seal/pasta_3_seal.h"
#include "ciphers/common_Zp/matrix.h"
#include "ciphers/common_Zp/SEAL_Cipher.h"
#include "seal/seal.h"  // Include SEAL library
#include "ciphers/kreyvium/tfhe/kreyvium_tfhe.h"
#include "ciphers/kreyvium/plain/kreyvium_plain.h"

using namespace std;
namespace py = pybind11;

std::vector<uint64_t> key_={0x07530, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
    0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd, 0x0d408, 0x01b17,
    0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa, 0x09e80, 0x0e253, 0x03f49,
    0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc, 0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6,
    0x07da9, 0x079bd, 0x08e84, 0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4,
    0x04383, 0x05d65, 0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea,
    0x096db, 0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
    0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02, 0x083b1,
    0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5, 0x0161c, 0x0e94d,
    0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb, 0x08529, 0x027c9, 0x010bc,
    0x079ca, 0x01ff1, 0x0219a, 0x00130, 0x0ff77, 0x012fb, 0x03ca6, 0x0d27d,
    0x05747, 0x0fa91, 0x00766, 0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e,
    0x08b0e, 0x08e59, 0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f,
    0x0a83e, 0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
    0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86, 0x0503a,
    0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b, 0x0cb90, 0x00c33,
    0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8, 0x0f107, 0x038ec, 0x0b014,
    0x007eb, 0x06335, 0x0afcc, 0x0d55c, 0x0a816, 0x0fa07, 0x05864, 0x0dc8f,
    0x07720, 0x0deef, 0x095db, 0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7,
    0x0b21a, 0x0ca98, 0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040,
    0x09bc5, 0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
    0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3, 0x08489,
    0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5, 0x06aac, 0x0a504,
    0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454, 0x04075, 0x06803, 0x03df5,
    0x091a0, 0x0d481, 0x09f04, 0x05c54, 0x0d54f, 0x00344, 0x09ffc, 0x00262,
    0x01fbf, 0x0461c, 0x01985, 0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f,
    0x03764, 0x041ad, 0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc,
    0x03249, 0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
    0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b, 0x00c59,
    0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495, 0x07d5a, 0x02d4,
    0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea, 0x0fbb6, 0x09e45, 0x0e9db,
    0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf};

std::vector<uint64_t> key1= {0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39,
    0x019e0, 0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd,
    0x0d408, 0x01b17, 0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa,
    0x09e80, 0x0e253, 0x03f49, 0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc,
    0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6, 0x07da9, 0x079bd, 0x08e84,
    0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4, 0x04383, 0x05d65,
    0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea, 0x096db,
    0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
    0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02,
    0x083b1, 0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5,
    0x0161c, 0x0e94d, 0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb,
    0x08529, 0x027c9, 0x010bc, 0x079ca, 0x01ff1, 0x0219a, 0x00130,
    0x0ff77, 0x012fb, 0x03ca6, 0x0d27d, 0x05747, 0x0fa91, 0x00766,
    0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e, 0x08b0e, 0x08e59,
    0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f, 0x0a83e,
    0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
    0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86,
    0x0503a, 0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b,
    0x0cb90, 0x00c33, 0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8,
    0x0f107, 0x038ec, 0x0b014, 0x007eb, 0x06335, 0x0afcc, 0x0d55c,
    0x0a816, 0x0fa07, 0x05864, 0x0dc8f, 0x07720, 0x0deef, 0x095db,
    0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7, 0x0b21a, 0x0ca98,
    0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040, 0x09bc5,
    0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
    0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3,
    0x08489, 0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5,
    0x06aac, 0x0a504, 0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454,
    0x04075, 0x06803, 0x03df5, 0x091a0, 0x0d481, 0x09f04, 0x05c54,
    0x0d54f, 0x00344, 0x09ffc, 0x00262, 0x01fbf, 0x0461c, 0x01985,
    0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f, 0x03764, 0x041ad,
    0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc, 0x03249,
    0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
    0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b,
    0x00c59, 0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495,
    0x07d5a, 0x02d4,  0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea,
    0x0fbb6, 0x09e45, 0x0e9db, 0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8,
    0x0a3a4, 0x03bcd, 0x036d9, 0x05acf};

//dummy key the size of the key with only 0x00000
std::vector<uint64_t> dummy_key(key1.size(), 0x00000);



seal::Ciphertext deserialize_ciphertext(const py::bytes &bytes, const seal::EncryptionParameters &params) {
    std::string serialized = bytes.cast<std::string>();  // Get the raw string from py::bytes
    std::stringstream ss(serialized);  // Use stringstream for deserialization
    
    seal::SEALContext context(params);
    seal::Ciphertext ct(context);  // Initialize Ciphertext with the SEALContext
    ct.load(context, ss);  // Load the serialized data into the Ciphertext
    return ct;
}

// 1. Serialization functions for PASTA_SEAL
py::bytes serialize_pasta_seal(const PASTA_3::PASTA_SEAL& pasta) {
    std::stringstream ss(std::ios::binary);
    pasta.save_with_sk(ss);
    return py::bytes(ss.str());
}

std::unique_ptr<PASTA_3::PASTA_SEAL> deserialize_pasta_seal(const py::bytes& data, std::shared_ptr<seal::SEALContext> context) {
    std::string serialized = data.cast<std::string>();
    std::stringstream ss(serialized, std::ios::binary);

    auto pasta = std::make_unique<PASTA_3::PASTA_SEAL>(dummy_key, context);
    pasta->load_with_sk(ss);
    return pasta;
                                        
}

std::vector<uint64_t> key= {0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39,
    0x019e0, 0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd,
    0x0d408, 0x01b17, 0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa,
    0x09e80, 0x0e253, 0x03f49, 0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc,
    0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6, 0x07da9, 0x079bd, 0x08e84,
    0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4, 0x04383, 0x05d65,
    0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea, 0x096db,
    0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
    0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02,
    0x083b1, 0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5,
    0x0161c, 0x0e94d, 0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb,
    0x08529, 0x027c9, 0x010bc, 0x079ca, 0x01ff1, 0x0219a, 0x00130,
    0x0ff77, 0x012fb, 0x03ca6, 0x0d27d, 0x05747, 0x0fa91, 0x00766,
    0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e, 0x08b0e, 0x08e59,
    0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f, 0x0a83e,
    0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
    0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86,
    0x0503a, 0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b,
    0x0cb90, 0x00c33, 0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8,
    0x0f107, 0x038ec, 0x0b014, 0x007eb, 0x06335, 0x0afcc, 0x0d55c,
    0x0a816, 0x0fa07, 0x05864, 0x0dc8f, 0x07720, 0x0deef, 0x095db,
    0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7, 0x0b21a, 0x0ca98,
    0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040, 0x09bc5,
    0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
    0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3,
    0x08489, 0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5,
    0x06aac, 0x0a504, 0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454,
    0x04075, 0x06803, 0x03df5, 0x091a0, 0x0d481, 0x09f04, 0x05c54,
    0x0d54f, 0x00344, 0x09ffc, 0x00262, 0x01fbf, 0x0461c, 0x01985,
    0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f, 0x03764, 0x041ad,
    0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc, 0x03249,
    0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
    0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b,
    0x00c59, 0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495,
    0x07d5a, 0x02d4,  0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea,
    0x0fbb6, 0x09e45, 0x0e9db, 0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8,
    0x0a3a4, 0x03bcd, 0x036d9, 0x05acf};


size_t modulusa=65537;

py::bytes serialize_ciphertext(const seal::Ciphertext &ct) {
    std::stringstream ss;
    ct.save(ss);
    return py::bytes(ss.str());
}



py::list serialize_ciphertext_deep_nested(py::list input) {
    py::list result;
    for (auto &level1 : input) {
        py::list level1_serialized;
        for (auto &level2 : level1.cast<py::list>()) {
            py::list level2_serialized;
            for (auto &ct_item : level2.cast<py::list>()) {
                seal::Ciphertext ct = ct_item.cast<seal::Ciphertext>();
                std::stringstream ss;
                ct.save(ss);
                level2_serialized.append(py::bytes(ss.str()));
            }
            level1_serialized.append(level2_serialized);
        }
        result.append(level1_serialized);
    }
    return result;
}

py::list deserialize_ciphertext_deep_nested(py::list input, std::shared_ptr<seal::SEALContext> context) {
    py::list result;
    for (auto &level1 : input) {
        py::list level1_deserialized;
        for (auto &level2 : level1.cast<py::list>()) {
            py::list level2_deserialized;
            for (auto &bytes_item : level2.cast<py::list>()) {
                std::stringstream ss(bytes_item.cast<std::string>());
                seal::Ciphertext ct;
                ct.load(*context, ss);
                level2_deserialized.append(ct);
            }
            level1_deserialized.append(level2_deserialized);
        }
        result.append(level1_deserialized);
    }
    return result;
}

py::list serialize_ciphertext_nested(py::list input) {
    py::list result;
    for (auto &level1 : input) {
        py::list level1_serialized;
        for (auto &ct_item : level1.cast<py::list>()) {
            seal::Ciphertext ct = ct_item.cast<seal::Ciphertext>();
            std::stringstream ss;
            ct.save(ss);
            level1_serialized.append(py::bytes(ss.str()));
        }
        result.append(level1_serialized);
    }
    return result;
}

py::list deserialize_ciphertext_nested(py::list input, std::shared_ptr<seal::SEALContext> context) {
    py::list result;
    for (auto &level1 : input) {
        py::list level1_deserialized;
        for (auto &bytes_item : level1.cast<py::list>()) {
            std::stringstream ss(bytes_item.cast<std::string>());
            seal::Ciphertext ct;
            ct.load(*context, ss);
            level1_deserialized.append(ct);
        }
        result.append(level1_deserialized);
    }
    return result;
}




// Helper function to convert a 3D py::list into a std::vector
std::vector<std::vector<std::vector<seal::Ciphertext>>> convert_to_3d_vector(py::list py_list) {
    std::vector<std::vector<std::vector<seal::Ciphertext>>> result;
    
    for (py::handle level1 : py_list) {
        py::list list1 = py::cast<py::list>(level1);
        std::vector<std::vector<seal::Ciphertext>> vec1;
        
        for (py::handle level2 : list1) {
            py::list list2 = py::cast<py::list>(level2);
            std::vector<seal::Ciphertext> vec2;
            
            for (py::handle item : list2) {
                seal::Ciphertext ct = item.cast<seal::Ciphertext>();
                vec2.push_back(ct);
            }
            vec1.push_back(vec2);
        }
        result.push_back(vec1);
    }
    
    return result;
}



PYBIND11_MAKE_OPAQUE(std::vector<seal::Ciphertext>);
PYBIND11_MAKE_OPAQUE(std::vector<std::vector<seal::Ciphertext>>);

PYBIND11_MODULE(exemplo, m) {
    m.doc() = "Pasta-3 plain C++ implementation with pickling support";

    m.def("serialize_ciphertext_deep_nested", &serialize_ciphertext_deep_nested, "Serialize list or list of lists of ciphertexts");
    m.def("deserialize_ciphertext_deep_nested", &deserialize_ciphertext_deep_nested, py::arg("input"), py::arg("context"));

    m.def("serialize_ciphertext_nested", &serialize_ciphertext_nested, "Serialize list or list of lists of ciphertexts");
    m.def("deserialize_ciphertext_nested", &deserialize_ciphertext_nested, py::arg("input"), py::arg("context"));


    m.def("serialize_ciphertext", &serialize_ciphertext);

    m.def("serialize_ciphertext_list", [](const std::vector<seal::Ciphertext> &cts) {
        std::vector<py::bytes> serialized_list;
        for (const auto &ct : cts) {
            std::stringstream ss;
            ct.save(ss);
            serialized_list.push_back(py::bytes(ss.str()));
        }
        return serialized_list;
    });

    py::class_<PASTA_3::PASTA>(m, "Pasta3Plain")
        .def(py::init<const std::vector<uint64_t>&, uint64_t>())
        .def("encrypt_plain", &PASTA_3::PASTA::encrypt)
        .def("decrypt_plain", &PASTA_3::PASTA::decrypt)
        // Add pickling support
        .def("__getstate__", [](const PASTA_3::PASTA& p) {
            // Serialize the key and modulus into a tuple
            // swithc for p.getkey() and p.getmodulus()
            return py::make_tuple(key, modulusa);
        })
        .def("__setstate__", [](PASTA_3::PASTA& p, py::tuple t) {
            if (t.size() != 2) {
                throw std::runtime_error("Invalid state!");
            }
            // Deserialize the key and modulus from the tuple
            std::vector<uint64_t> key = t[0].cast<std::vector<uint64_t>>();
            uint64_t modulus = t[1].cast<uint64_t>();
            // Reconstruct the object
            new (&p) PASTA_3::PASTA(key, modulus);
        });
    
    py::class_<PASTA_3::PASTA_SEAL>(m, "Pasta3Seal")
        .def(py::init<std::vector<uint64_t>, std::shared_ptr<seal::SEALContext>>())
        .def("get_cipher_name", &PASTA_3::PASTA_SEAL::get_cipher_name)
        .def("encrypt_key", &PASTA_3::PASTA_SEAL::encrypt_key)
        .def("add_gk_indices", &PASTA_3::PASTA_SEAL::add_gk_indices)
        .def("create_gk", &PASTA_3::PASTA_SEAL::create_gk)
        .def("activate_bsgs", &PASTA_3::PASTA_SEAL::activate_bsgs)
        .def("print_parameters", &PASTA_3::PASTA_SEAL::print_parameters)
        .def("HE_decrypt", [](PASTA_3::PASTA_SEAL &self, std::vector<uint64_t> ciphertexts, bool batch_encoder) {

            std::vector<seal::Ciphertext> result = self.HE_decrypt(ciphertexts, batch_encoder);
        
            // Convert std::vector<seal::Ciphertext> to Python list
            py::list py_result;
            for (auto &ciphertext : result) {
                py_result.append(ciphertext);  // Convert each Ciphertext to Python object
            }
            return py_result;  // Return as a Python list
        })
        .def("decrypt_result", [](PASTA_3::PASTA_SEAL &self, py::list py_ciphertexts, bool batch_encoder) {
            // Convert Python list to std::vector<seal::Ciphertext>
            std::vector<seal::Ciphertext> ciphertexts;
            for (auto& item : py_ciphertexts) {
                ciphertexts.push_back(item.cast<seal::Ciphertext>());
            }

            // Call the original function with the converted vector
            std::vector<uint64_t> result = self.decrypt_result(ciphertexts, batch_encoder);
            
            // Return the result as a Python list
            return py::cast(result);
        })
        .def("deserialize_and_decrypt_single", [](PASTA_3::PASTA_SEAL &self, py::bytes serialized_ct, bool batch_encoder) {
            seal::SEALContext &context = *self.get_context();  // Get reference to context
            std::stringstream ss(serialized_ct.cast<std::string>());
            seal::Ciphertext ct;
            ct.load(context, ss);
        
            std::vector<seal::Ciphertext> ciphertexts = {ct};  // Wrap in vector to match decrypt_result signature
            std::vector<uint64_t> result = self.decrypt_result(ciphertexts, batch_encoder);
        
            return py::cast(result);  // Return Python list[int]
        })
        .def("set_secret_key_encrypted", [](PASTA_3::PASTA_SEAL &self, py::list py_ciphertexts) {
            std::vector<std::string> serialized_ciphertexts;

            for (auto &item : py_ciphertexts) {
                serialized_ciphertexts.push_back(item.cast<std::string>());  //  Convert Python bytes to std::string
            }

            self.set_secret_key_encrypted(serialized_ciphertexts);  //
        })
        // Bind get_secret_key_encrypted: Convert std::vector<seal::Ciphertext> to Python list
        .def("get_secret_key_encrypted", [](PASTA_3::PASTA_SEAL &self) {
            std::vector<std::string> serialized_ciphertexts = self.get_secret_key_encrypted();
            py::list py_result;
            for (const auto& str : serialized_ciphertexts) {
                py_result.append(py::bytes(str));  // Convert to Python bytes
            }
            return py_result;
        })
        .def("save_with_sk", &PASTA_3::PASTA_SEAL::save_with_sk)
        .def("save_without_sk", &PASTA_3::PASTA_SEAL::save_without_sk)
        .def("load_with_sk", &PASTA_3::PASTA_SEAL::load_with_sk)
        .def("load_without_sk", &PASTA_3::PASTA_SEAL::load_without_sk)
        .def("update_he_keys",[](PASTA_3::PASTA_SEAL &self, py::bytes state) {
            try {
                std::string serialized = state.cast<std::string>();
                std::istringstream iss(serialized, std::ios::binary);  // Must use binary mode!
                self.load_without_sk(iss);
            } catch (const std::exception& e) {
                throw std::runtime_error(std::string("Failed to update HE keys: ") + e.what());
            }
        })
        .def("__getstate__", [](const PASTA_3::PASTA_SEAL &self) {
            std::ostringstream oss;
            self.save_without_sk(oss);  // Ensure you have a `save` function in C++
            return py::bytes(oss.str());
        })
        .def("__setstate__", [](PASTA_3::PASTA_SEAL &self, py::bytes state) {
            std::string serialized = state.cast<std::string>();
            std::istringstream iss(serialized);
            //std::cout << "Loading pasta state\n";
        
            self.load_with_sk(iss);  // Modify the existing object
            
            //std::cout << "Pasta state loaded\n";
        })
        .def("multiply_inplace_plain_list", [](PASTA_3::PASTA_SEAL &self, py::list py_ciphertexts, uint64_t plaintext) {
            for (auto item : py_ciphertexts) {
                auto ciphertext = item.cast<seal::Ciphertext>();
                self.multiply_inplace_plaintext(ciphertext, plaintext);
            }
        })
        .def("add_multiply_inplace_plain", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext, uint64_t plaintext) {
            auto initial_value = new seal::Ciphertext(py_ciphertext);
            for(int i =1; i<plaintext; i++){
                self.add_inplace_ciphertext(py_ciphertext, *initial_value);
            } 
        })
        .def("multiply_inplace_plain", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext, float plaintext) {
                self.multiply_inplace_plaintext(py_ciphertext, plaintext);   
        })
        .def("multiply_inplace_ciphertext", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext1, seal::Ciphertext& py_ciphertext2) {
            self.multiply_inplace_ciphertext(py_ciphertext1, py_ciphertext2);   
        })
        .def("add_inplace_plain", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext, uint64_t plaintext) {
                self.add_inplace_plaintext(py_ciphertext, plaintext);   
        })
        
        .def("add_inplace_ciphertext", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext1, seal::Ciphertext& py_ciphertext2) {
            self.add_inplace_ciphertext(py_ciphertext1, py_ciphertext2);   
        })
        .def("sub_inplace_plain", [](PASTA_3::PASTA_SEAL &self, seal::Ciphertext& py_ciphertext, uint64_t plaintext) {
            self.sub_inplace_plaintext(py_ciphertext, plaintext);   
        })
        .def("sum_ciphertext", [](PASTA_3::PASTA_SEAL &self,  py::list& aggregated,py::list& results) {
            std::cout<<"entrou\n";

            for (py::handle result_pair : results) {
                // Unpack the pair (he_ciphertexts, weight)
                py::tuple result_tuple = py::cast<py::tuple>(result_pair);
                py::list he_ciphertexts = py::cast<py::list>(result_tuple[0]);  // First element is the he_ciphertexts
                uint64_t weight = py::cast<uint64_t>(result_tuple[1]);  // Second element is the weight
        
                // Now process the he_ciphertexts (which is a 3D list)
                for (py::handle level1 : he_ciphertexts) {
                    py::list list1 = py::cast<py::list>(level1);  // First level of the list
                    for (py::handle level2 : list1) {
                        py::list list2 = py::cast<py::list>(level2);  // Second level of the list
                        for (py::handle item : list2) {
                            seal::Ciphertext ct = item.cast<seal::Ciphertext>();  // Cast each item to seal::Ciphertext
                            // Do something with the Ciphertext (ct) and weight...
                        }
                    }
                }
            }

            std::cout<<"saiu\n";
        })
        .def("he_decrypt_all", [](PASTA_3::PASTA_SEAL &self, py::list py_ciphertexts, bool batch_encoder) {
            
            py::list decrypted_results;

             for (auto &item : py_ciphertexts) {
                py::list py_chunk = py::cast<py::list>(item);
                py::list py_decrypted_outer;

                for (auto &chunk : py_chunk) {
                    std::vector<uint64_t> chunk_vector;

                    for (auto &num : chunk.cast<py::list>()) {
                        chunk_vector.push_back(num.cast<uint64_t>());
                    }

                    std::vector<seal::Ciphertext> decrypted = self.HE_decrypt(chunk_vector, batch_encoder);

                    // Wrap the result of HE_decrypt into an inner list
                    py::list py_inner;
                    for (auto &num : decrypted) {
                        py_inner.append(num);
                    }

                    // Append the inner list (e.g., [<Ciphertext>]) to the outer list (=> [[<Ciphertext>]])
                    py_decrypted_outer.append(py_inner);
                }

                // Append the full wrapped list for this chunk (=> [[[<Ciphertext>]]])
                decrypted_results.append(py_decrypted_outer);
            }

            return decrypted_results; 
            
            
        })
        .def("he_decrypt_all_v2", [](PASTA_3::PASTA_SEAL &self, py::list py_ciphertexts, bool batch_encoder) {
            
             py::list decrypted_results;
            // Cast the full input to C++ nested vector
             auto cpp_ciphertexts = py::cast<std::vector<std::vector<std::vector<uint64_t>>>>(py_ciphertexts);

            for ( auto& enc_chunks : cpp_ciphertexts) {
                py::list py_decrypted_outer;

                for ( auto& chunk : enc_chunks) {
                    std::vector<seal::Ciphertext> decrypted = self.HE_decrypt(chunk, batch_encoder);

                    py::list py_inner;
                    for ( auto& ct : decrypted) {
                        py_inner.append(ct);
                    }

                    py_decrypted_outer.append(py_inner);
                }

                decrypted_results.append(py_decrypted_outer);
            }

            return decrypted_results; 
            
        })
        .def("get_temp_secret_key_encrypted",&PASTA_3::PASTA_SEAL::get_temp_secret_key_encrypted)
        .def("define_temp_secret_key", [](PASTA_3::PASTA_SEAL &self, const std::string &hex_poly) {
            seal::Plaintext client_key(hex_poly);  // reconstruct plaintext from hex

            // Convert expected plaintext to string for comparison
            std::string expected = self.get_temp_secret_key_encrypted();

            if (client_key.to_string() != expected) {
                throw std::runtime_error("The provided key does not match the expected format.");
            }
            cout << "Key matches expected format." << std::endl;

        })
        .def("encrypt_masked_key",&PASTA_3::PASTA_SEAL::encrypt_masked_key)
        .def("remove_mask",&PASTA_3::PASTA_SEAL::remove_mask);



    py::class_<seal::SEALContext, std::shared_ptr<seal::SEALContext>>(m, "SEALContext")
        .def("parameters_set", &seal::SEALContext::parameters_set);

    py::class_<SEALZpCipher>(m, "SEALZpCipher")
        .def("create_context", &SEALZpCipher::create_context);
        py::class_<seal::Ciphertext>(m, "Ciphertext")
        .def(py::init<>())  // Default constructor
        .def("serialize", &serialize_ciphertext)
        .def("deserialize", &deserialize_ciphertext)
        .def(py::pickle(
            [](const seal::Ciphertext &ct) { 
                return serialize_ciphertext(ct);  // __getstate__
            },
            [](const py::bytes &bytes) { 
                // Pass the EncryptionParameters to deserialize correctly
                return deserialize_ciphertext(bytes, seal::EncryptionParameters(seal::scheme_type::bfv));  // __setstate__
            }
        ));


}