using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;

namespace APIMonitor.Native
{
    /// <summary>
    /// Reads Windows.Win32.winmd (Microsoft.Windows.SDK.Win32Metadata NuGet)
    /// at startup and exposes a "module!FunctionName -> signature" lookup.
    /// Used to format Hook DLL events with real parameter names and types
    /// instead of bare hex.
    /// </summary>
    public sealed class Win32MetadataResolver
    {
        public sealed class ParamInfo
        {
            public string Name;     // e.g. "lpFileName"
            public string TypeName; // e.g. "PWSTR", "DWORD", "HANDLE"
            public bool   IsOut;
        }

        public sealed class ApiSignature
        {
            public string ModuleDll; // e.g. "kernel32.dll" (lower-case)
            public string Name;      // exported name (no decoration)
            public string ReturnType;
            public ParamInfo[] Params;
        }

        // key: lowercase "module!name", e.g. "kernel32.dll!CreateFileW"
        private readonly Dictionary<string, ApiSignature> _byKey =
            new Dictionary<string, ApiSignature>(StringComparer.OrdinalIgnoreCase);
        // fallback: lookup just by function name (Win32Metadata describes
        // TlsGetValue only under kernel32, but the same export also lives in
        // kernelbase as a forwarder; match by name only as a last resort).
        private readonly Dictionary<string, ApiSignature> _byName =
            new Dictionary<string, ApiSignature>(StringComparer.OrdinalIgnoreCase);

        public int Count => _byKey.Count;

        public ApiSignature Lookup(string module, string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            ApiSignature sig;
            if (!string.IsNullOrEmpty(module))
            {
                if (_byKey.TryGetValue(module + "!" + name, out sig)) return sig;
                if (!module.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                    && _byKey.TryGetValue(module + ".dll!" + name, out sig)) return sig;
            }
            // Last resort: any module that has this export name.
            _byName.TryGetValue(name, out sig);
            return sig;
        }

        public static Win32MetadataResolver Load(string winmdPath)
        {
            var r = new Win32MetadataResolver();
            r.LoadInternal(winmdPath);
            return r;
        }

        private void LoadInternal(string winmdPath)
        {
            if (!File.Exists(winmdPath)) return;

            using (var stream = File.OpenRead(winmdPath))
            using (var pe = new PEReader(stream))
            {
                var md = pe.GetMetadataReader();

                foreach (var typeHandle in md.TypeDefinitions)
                {
                    var typeDef = md.GetTypeDefinition(typeHandle);
                    // Win32Metadata puts P/Invoke methods on classes named like
                    // Apis (one per "module"). Walk every method that has a
                    // P/Invoke import directive.
                    foreach (var methHandle in typeDef.GetMethods())
                    {
                        var meth = md.GetMethodDefinition(methHandle);
                        var imp  = meth.GetImport();
                        if (imp.Module.IsNil) continue;

                        var moduleRef = md.GetModuleReference(imp.Module);
                        string moduleName = md.GetString(moduleRef.Name);
                        if (string.IsNullOrEmpty(moduleName)) continue;
                        if (!moduleName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                            moduleName += ".dll";

                        string apiName = md.GetString(meth.Name);
                        if (string.IsNullOrEmpty(apiName)) continue;

                        // Decode the signature to get return type + parameter types.
                        var sig = meth.DecodeSignature(new TypeNameProvider(md), null);

                        var paramHandles = meth.GetParameters();
                        var paramInfos = new ParamInfo[sig.ParameterTypes.Length];
                        // Default names if Param table is missing/short.
                        for (int i = 0; i < paramInfos.Length; i++) {
                            paramInfos[i] = new ParamInfo {
                                Name = "p" + (i + 1),
                                TypeName = sig.ParameterTypes[i],
                                IsOut = false,
                            };
                        }
                        foreach (var ph in paramHandles) {
                            var p = md.GetParameter(ph);
                            int idx = p.SequenceNumber - 1; // 0 is return
                            if (idx < 0 || idx >= paramInfos.Length) continue;
                            paramInfos[idx].Name = md.GetString(p.Name);
                            paramInfos[idx].IsOut = (p.Attributes & ParameterAttributes.Out) != 0;
                        }

                        var apiSig = new ApiSignature {
                            ModuleDll  = moduleName,
                            Name       = apiName,
                            ReturnType = sig.ReturnType,
                            Params     = paramInfos,
                        };

                        var key = moduleName + "!" + apiName;
                        _byKey[key] = apiSig;
                        // also index by-name as a fallback for forwarder
                        // exports (kernel32!TlsGetValue forwards to
                        // kernelbase!TlsGetValue - the metadata describes
                        // only the kernel32 entry but our Hook DLL emits
                        // the call under whichever module the IAT points
                        // at).
                        if (!_byName.ContainsKey(apiName)) {
                            _byName[apiName] = apiSig;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Tiny SignatureTypeProvider that returns each type as a friendly
        /// name string ("DWORD", "PWSTR", "HANDLE" or just "T" for unknown).
        /// </summary>
        private sealed class TypeNameProvider : ISignatureTypeProvider<string, object>
        {
            private readonly MetadataReader _md;
            public TypeNameProvider(MetadataReader md) { _md = md; }

            public string GetPrimitiveType(PrimitiveTypeCode typeCode)
            {
                switch (typeCode) {
                    case PrimitiveTypeCode.Boolean: return "BOOL";
                    case PrimitiveTypeCode.Byte:    return "BYTE";
                    case PrimitiveTypeCode.SByte:   return "CHAR";
                    case PrimitiveTypeCode.Char:    return "WCHAR";
                    case PrimitiveTypeCode.Int16:   return "SHORT";
                    case PrimitiveTypeCode.UInt16:  return "USHORT";
                    case PrimitiveTypeCode.Int32:   return "INT";
                    case PrimitiveTypeCode.UInt32:  return "DWORD";
                    case PrimitiveTypeCode.Int64:   return "INT64";
                    case PrimitiveTypeCode.UInt64:  return "UINT64";
                    case PrimitiveTypeCode.Single:  return "FLOAT";
                    case PrimitiveTypeCode.Double:  return "DOUBLE";
                    case PrimitiveTypeCode.IntPtr:  return "INT_PTR";
                    case PrimitiveTypeCode.UIntPtr: return "UINT_PTR";
                    case PrimitiveTypeCode.String:  return "PWSTR";
                    case PrimitiveTypeCode.Void:    return "void";
                    case PrimitiveTypeCode.Object:  return "PVOID";
                    default:                        return typeCode.ToString();
                }
            }

            public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte rawTypeKind) {
                var t = r.GetTypeDefinition(h);
                return r.GetString(t.Name);
            }
            public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte rawTypeKind) {
                var t = r.GetTypeReference(h);
                return r.GetString(t.Name);
            }
            public string GetTypeFromSpecification(MetadataReader r, object g, TypeSpecificationHandle h, byte rawTypeKind) {
                return "T";
            }

            public string GetSZArrayType(string elementType)        => elementType + "[]";
            public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[]";
            public string GetByReferenceType(string elementType)    => elementType + "&";
            public string GetPointerType(string elementType)        => elementType + "*";
            public string GetPinnedType(string elementType)         => elementType;
            public string GetGenericMethodParameter(object g, int i) => "T" + i;
            public string GetGenericTypeParameter(object g, int i)   => "T" + i;
            public string GetGenericInstantiation(string genericType, System.Collections.Immutable.ImmutableArray<string> typeArguments) => genericType;
            public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
            public string GetFunctionPointerType(MethodSignature<string> signature) => "PVOID";
        }
    }
}
