import java.awt.Desktop;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;


public class Images extends Thread {
	
	public void run()
	{

		// Directory path here
		String path = "Files/Pictures"; 

		String files;
		ArrayList<String> allFiles = new ArrayList<String>();
		File folder = new File(path);
		File[] listOfFiles = folder.listFiles(); 

		for (int i = listOfFiles.length-1; i >= 0 ; i--) 
		{	 
			if (listOfFiles[i].isFile()) 
			{
				files = listOfFiles[i].getName();
				allFiles.add(files);
				System.out.println(files);
			}
		}

		BufferedWriter bw;
		try {
			bw = new BufferedWriter(new FileWriter("AllPictures.html"));
			bw.write("<html><head><title>New Page</title></head><body><p>Recieved Pictures</p></body></html>");
			bw.write("<table>");
			for(String str : allFiles) {
				bw.write("<center><tr>");
				bw.write("<tr>"+str + "</tr>");
				bw.write("<img border=\"0\" src = Files/Pictures/" + str + " width=\"800\" height=\"600\">");
				bw.write("</tr></center>");				
				bw.write("<tr>      </br>       </tr>");
			}
			bw.write("</table>");
			System.out.println("Done!");
			bw.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if( !java.awt.Desktop.isDesktopSupported() ) {

			System.err.println( "Desktop is not supported (fatal)" );
			System.exit( 1 );
		}



		Desktop desktop = Desktop.getDesktop();

		if( !desktop.isSupported( java.awt.Desktop.Action.BROWSE ) ) {

			System.err.println( "Desktop doesn't support the browse action (fatal)" );
			System.exit( 1 );
		}



		try {

			java.net.URI uri = new java.net.URI("AllPictures.html"  );
			desktop.browse( uri );
		}
		catch ( Exception e ) {

			System.err.println( e.getMessage() );
		}

	}

}

