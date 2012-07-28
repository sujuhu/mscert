// mscert.cpp : Defines the entry point for the console application.
//

#include <Python.h>
#include <windows.h>
#include "../../base/string.h"
#include "../libcert.h"

/*
Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject)
{
	PyObject *pException;

	if(!pObject) {
		pException = PyErr_Occurred();
		if(pException)
			PyErr_Print();
		return NULL;
	}

	return pObject;
}

extern "C"
static PyObject* pycert_verify(PyObject* self, PyObject* args) 
{ 
	//获取文件的签名值
	char* sample_file = NULL;

	if (!args || PyObject_Length(args)!=1) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 1 expected: (sample_file)");
		return NULL;
	}

	PyObject* py_sample_file = PyTuple_GetItem(args, 0);
	if(!check_object(py_sample_file)) {
		PyErr_SetString(PyExc_ValueError, "Can't get sample file from arguments");
	}

	sample_file = PyString_AsString(py_sample_file);
	if( !LoadCert() ) {
		PyErr_SetString(PyExc_TypeError, 
			"Load cert failed");
	}

	PUBSIG	cert = {0};
	if( !VerifyCertByFile( sample_file, &cert ) ) {
		Py_RETURN_NONE;
	}

	if( cert.bSigned ) {
		//有签名证书
		PyObject* pDict = PyDict_New();
		PyDict_SetItem( pDict,  Py_BuildValue( "s", "name"), 
								Py_BuildValue( "s", cert.Publisher ) );

		CHAR hexstr[41] = {0};
		DWORD size = sizeof( hexstr );
		BufferToHexString( cert.Hash, sizeof( cert.Hash ), hexstr, size );
		PyDict_SetItem( pDict, Py_BuildValue( "s", "sign"), 
							Py_BuildValue( "s", hexstr ) );
		return pDict;
	} else {
		//没有签名证书
		Py_RETURN_NONE;
	}
} 

static PyMethodDef pycertMethods[] =
{ 
	{"verify",		pycert_verify,	METH_VARARGS, "verify( sample_file )"}, 
	{NULL, NULL, 0, NULL}
}; 

PyMODINIT_FUNC initpycert() 
{ 
	Py_InitModule("pycert", pycertMethods); 
}

