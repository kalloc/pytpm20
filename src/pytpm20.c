#include "pytpm20.h"

#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))

#define py_check_state(state) \
    if(state->ctx.ectx == NULL) { \
        PyErr_SetString(PyExc_SystemError, "tcti device not inited, module->setup() first"); \
        return NULL; \
    }

#define py_check_rc(rc, err) \
    if(rc != TPM2_RC_SUCCESS) { \
        PyErr_SetString(state->error, Tss2_RC_Decode(rc)); \
        goto err; \
    }

static struct PyModuleDef py_module;
struct module_state {
    context ctx;
    PyObject *error;
};


static PyObject *py_init_tpm_device(PyObject *self, PyObject *args){
    struct module_state *state;
    PyObject* module;
    TPM2_RC rc;

    if((module = PyState_FindModule(&py_module)) == NULL) {
        return NULL;
    }

    state = GETSTATE(module);
    if(state->ctx.ectx != NULL) {
        return Py_BuildValue("i", true);
    }

    rc = init_tpm_device("device", &state->ctx);
    py_check_rc(rc, err);

    return Py_BuildValue("i", true);
err:
    return NULL;
}

static PyObject *py_getrandom(PyObject *self, PyObject *args){
    struct module_state *state;
    PyObject *module, *result = NULL;
    unsigned char *buf;
    TPM2_RC rc = TPM2_RC_SUCCESS;
    size_t len = 0;

    if(!PyArg_ParseTuple(args, "K", &len)){
        return NULL;
    }

    if(len > 64) {
        PyErr_SetString(PyExc_TypeError, "Allow only 64 bytes to be allocated");
        return NULL;
    }

    if((module = PyState_FindModule(&py_module)) == NULL) {
        return NULL;
    }

    state = GETSTATE(module);
    py_check_state(state);

    if((buf = malloc(len)) == NULL) {
        return PyErr_NoMemory();
    }

    rc = get_random(&state->ctx, &buf, &len);
    py_check_rc(rc, err);

    result = Py_BuildValue("y#", buf, len);

err:
    free(buf);
    return result;
}

static PyObject *py_sign(PyObject *self, PyObject *args){
    struct module_state *state;
    PyObject *module, *result = NULL;
    Py_ssize_t data_len = 0;
    unsigned char *data, *buf;
    TPM2_RC rc = TPM2_RC_SUCCESS;
    size_t buf_len;

    if((module = PyState_FindModule(&py_module)) == NULL) {
        return NULL;
    }

    state = GETSTATE(module);
    py_check_state(state);

    if(!PyArg_ParseTuple(args, "y#", &data, &data_len)){
        return NULL;
    }

    if(data_len > 1024) {
        PyErr_SetString(PyExc_TypeError, "Allow only 1024 bytes to be signed");
        goto err;
    }

    rc = sign(&state->ctx, data, data_len, &buf, &buf_len);
    py_check_rc(rc, err);

    result = Py_BuildValue("y#", buf, buf_len);
    free(buf);

err:
    return result;
}

static PyObject *py_public(PyObject *self, PyObject *args){
    struct module_state *state;
    PyObject *module, *result = NULL;
    unsigned char *buf;
    TPM2_RC rc = TPM2_RC_SUCCESS;
    size_t len = 0;

    if((module = PyState_FindModule(&py_module)) == NULL) {
        return NULL;
    }

    state = GETSTATE(module);
    py_check_state(state);

    rc = pub(&state->ctx, (unsigned char **)&buf, &len);
    py_check_rc(rc, err);

    result = Py_BuildValue("y#", buf, len);
    free(buf);

err:
    return result;
}

static PyMethodDef py_methods[] = {
	{
        "setup",
        (PyCFunction)py_init_tpm_device, METH_NOARGS,
        "setup() -> bool\n init device"
    },
	{
        "random", 
        (PyCFunction)py_getrandom, METH_VARARGS,
        "random(size: int) -> bytes\n Return random bytes from TPM"
    },
	{
        "sign", 
        (PyCFunction)py_sign, METH_VARARGS,
        "sign(data: bytes) -> bytes\n Sign and return signature"
    },
	{
        "public", 
        (PyCFunction)py_public, METH_NOARGS,
        "public() -> bytes\n Return public key"
    },
	{NULL, NULL, 0, NULL}
};


static int myextension_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int myextension_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef py_module = {
	PyModuleDef_HEAD_INIT,
	"tpm20",
	"tpm20 bindings",
	sizeof(struct module_state),
	py_methods,
    NULL,
    myextension_traverse,
    myextension_clear,
    NULL
};

PyMODINIT_FUNC PyInit__tpm20(void){
	PyObject *module;
    struct module_state *state;

    if((module = PyState_FindModule(&py_module)) != NULL) {
        Py_INCREF(module);
        return module;
    }

    if((module = PyModule_Create(&py_module)) == NULL) {
        return NULL;
    }

    if((state = GETSTATE(module)) == NULL) {
        Py_XDECREF(module);
        return NULL;
    }
    
    if((state->error = PyErr_NewException("tpm20.DriverException", NULL, NULL)) == NULL) {
        Py_XDECREF(module);
        return NULL;
    }

    return module;
}

