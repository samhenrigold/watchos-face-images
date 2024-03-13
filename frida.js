"use strict";

function watchImages() {
	ObjC.schedule(ObjC.mainQueue, function () {
        var getNativeFunction = function (ex, retVal, args) {
            return new NativeFunction(
                Module.findExportByName("UIKit", ex),
                retVal,
                args
            );
        };
    
        var UIImagePNGRepresentation = getNativeFunction('UIImagePNGRepresentation', 'pointer', ['pointer']);
    
        // Enumerate all instances of NTKFaceSnapshotViewController
        const instances = ObjC.chooseSync(
            ObjC.classes.NTKFaceSnapshotViewController
        );
    
        instances.forEach(function (instance) {
            // Access the _snapshotImage ivar
            const snapshotImage = instance.valueForKey_("_snapshotImage");
    
            // // Access the face ivar to get the file name
            const faceString = instance.valueForKey_("face").toString();
            // sanitize the string for a path name
            const fileName = faceString.replace(/[^a-zA-Z0-9]/g, "_");
    
            var png = new ObjC.Object(UIImagePNGRepresentation(snapshotImage));
            
            send({fileName: fileName, imageData: png.base64EncodedStringWithOptions_(0).toString()});
        });
    });
}

rpc.exports = {
	getWatchImages: watchImages,
};