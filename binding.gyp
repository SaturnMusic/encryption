{
  "targets": [
    {
      "target_name": "decryptor",
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "sources": [ "native/decryptor.cc" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ],
      'conditions': [
        ["OS=='linux'", {
          'libraries': [
            '-lcrypto',
            '-lssl'
          ]
        }],
        ["OS=='win'", {
          "include_dirs": [
            "<!@(node -p \"require('node-addon-api').include\")",
            "<(module_root_dir)\openssl\include"
          ],
          "link_settings": {
            "libraries": [
              "<(module_root_dir)\openssl\lib\libcrypto.lib",
              "<(module_root_dir)\openssl\lib\libssl.lib"
            ]
          },
          "variables": {
            "dll_files": [
              "<(module_root_dir)\openssl\libcrypto-1_1-x64.dll",
              "<(module_root_dir)\openssl\libssl-1_1-x64.dll"
            ]
          },
          "copies": [{
            "destination": "<(module_root_dir)/build/Release/",
            "files": [
              "<(module_root_dir)\openssl\libcrypto-1_1-x64.dll",
              "<(module_root_dir)\openssl\libssl-1_1-x64.dll"
            ]
          }]
        }]
      ]
      
    }
  ]
}